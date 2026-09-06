from __future__ import annotations

import ast
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Mapping

from .models import AIAnalysisRequest, AIAnalysisResult, AIProviderConfig, PromptBudget
from .rule_catalog import HeapRuleCatalog
from .validator import ALLOWED_ACTIONS, validate_ai_response


class ProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        kind: str = "response",
        retryable: bool = False,
        details: Mapping[str, object] | None = None,
    ):
        super().__init__(message)
        self.kind = kind
        self.retryable = retryable
        self.details = dict(details or {})


class LocalAIProvider(ABC):
    @abstractmethod
    def health_check(self) -> tuple[bool, str]:
        raise NotImplementedError

    @abstractmethod
    def list_models(self) -> tuple[str, ...]:
        raise NotImplementedError

    @abstractmethod
    def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        raise NotImplementedError


class OpenAICompatibleProvider(LocalAIProvider):
    """Small dependency-free client for LM Studio/OpenAI-compatible servers."""

    def __init__(self, config: AIProviderConfig):
        self.config = config

    def health_check(self) -> tuple[bool, str]:
        try:
            models = self.list_models()
        except ProviderError as error:
            return False, str(error)
        if not models:
            return False, "服务已连接，但未返回可用模型。"
        if self.config.model and self.config.model not in models:
            return False, (
                f"服务已连接，但未加载所需模型 {self.config.model}；"
                f"当前可用: {', '.join(models)}"
            )
        return True, f"已连接 {self.config.model}。"

    def list_models(self) -> tuple[str, ...]:
        payload = self._request_json("GET", "/models")
        data = payload.get("data") or payload.get("models") or []
        if not isinstance(data, list):
            raise ProviderError("/models 返回格式无效。")
        result = []
        for item in data:
            if isinstance(item, Mapping):
                model_id = str(item.get("id") or item.get("key") or item.get("model") or "")
            else:
                model_id = str(item)
            if model_id:
                result.append(model_id)
        return tuple(dict.fromkeys(result))

    def analyze(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        if not self.config.model.strip():
            raise ProviderError("请先选择 LM Studio 模型。", kind="model")
        started = time.monotonic()
        messages, budget, compact_static = self.prepare_messages(request, self.config)
        if not budget.fits:
            raise ProviderError(budget.diagnostic, kind="over_budget")
        body = {
            "model": self.config.model,
            "messages": messages,
            "temperature": max(0.0, min(2.0, float(self.config.temperature))),
            "max_tokens": max(256, min(32768, int(self.config.max_tokens))),
            "stream": False,
            "response_format": self._response_format(),
        }
        fallback_note = ""
        try:
            raw = self._request_json("POST", "/chat/completions", body)
        except ProviderError as structured_error:
            # Some small or older local models do not expose grammar-backed
            # structured output.  Retry once with the identical JSON-only
            # contract rather than requiring an OpenAI SDK.
            if not str(structured_error).startswith(("HTTP 400", "HTTP 422")):
                raise
            fallback_body = dict(body)
            fallback_body.pop("response_format", None)
            try:
                raw = self._request_json("POST", "/chat/completions", fallback_body)
                fallback_note = f"structured output 不可用，已回退为 JSON 文本：{structured_error}"
            except ProviderError:
                raise structured_error
        content = self._completion_content(raw)
        decoded = self._expand_compact_proposals(self._extract_json(content))
        proposals, diagnostics = validate_ai_response(decoded, request.source, request.source_hash)
        if compact_static:
            diagnostics = ("输入预算已精简重复 Heap IR；完整 EXP 未截断。", *diagnostics)
        if fallback_note:
            diagnostics = (fallback_note, *diagnostics)
        return AIAnalysisResult(
            generation=request.generation,
            source_hash=request.source_hash,
            proposals=proposals,
            diagnostics=diagnostics,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            model=self.config.model,
            prompt_version=request.prompt_version,
            candidate_audit=tuple(
                dict(item)
                for item in list(decoded.get("proposals") or [])[:4]
                if isinstance(item, Mapping)
            ),
        )

    def _request_json(self, method: str, path: str, payload: Mapping[str, object] | None = None) -> dict[str, object]:
        base_url = self.config.normalized_base_url()
        parsed_base = urllib.parse.urlsplit(base_url)
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
            raise ProviderError("Base URL 必须是有效的 http:// 或 https:// 地址。")
        if parsed_base.query or parsed_base.fragment:
            raise ProviderError("Base URL 不能包含 query 或 fragment。")
        url = base_url + "/" + path.lstrip("/")
        data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.config.api_token:
            headers["Authorization"] = f"Bearer {self.config.api_token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=max(1.0, float(self.config.timeout))) as response:
                raw = response.read(16 * 1024 * 1024)
        except urllib.error.HTTPError as error:
            try:
                detail = error.read(4096).decode("utf-8", errors="replace")
            except Exception:
                detail = ""
            retryable = error.code == 429 or error.code >= 500
            raise ProviderError(
                f"HTTP {error.code}: {detail or error.reason}",
                kind="offline" if retryable else "response",
                retryable=retryable,
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ProviderError(
                f"无法连接 {url}: {error}",
                kind="offline",
                retryable=True,
            ) from error
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProviderError("服务返回了无效 JSON。") from error
        if not isinstance(value, dict):
            raise ProviderError("服务返回 JSON 根节点不是对象。")
        return value

    @staticmethod
    def _completion_content(payload: Mapping[str, object]) -> str:
        choices = payload.get("choices") or []
        if not isinstance(choices, list) or not choices:
            raise ProviderError("chat completion 没有 choices。")
        first = choices[0]
        if not isinstance(first, Mapping):
            raise ProviderError("chat completion choice 格式无效。")
        message = first.get("message") or {}
        if isinstance(message, Mapping):
            content = message.get("content")
        else:
            content = first.get("text")
        if isinstance(content, list):
            content = "".join(str(item.get("text") or "") for item in content if isinstance(item, Mapping))
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("模型没有返回可解析内容。")
        return content

    @staticmethod
    def _extract_json(content: str) -> dict[str, object]:
        text = content.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            # Some compatible servers omit a supplied assistant prefill from
            # returned content. It is still accepted only after JSON parsing
            # and the strict proposal validator.
            if "{" not in text and "}" in text:
                try:
                    value = json.loads("{" + text)
                except json.JSONDecodeError:
                    value = None
                if isinstance(value, dict):
                    return value
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                raise ProviderError("模型输出不包含 JSON 对象。")
            try:
                value = json.loads(text[start : end + 1])
            except json.JSONDecodeError as error:
                raise ProviderError(
                    f"模型 JSON 解析失败: {error}",
                    details={"response_excerpt": text[:4096]},
                ) from error
        if not isinstance(value, dict):
            raise ProviderError("模型 JSON 根节点必须是对象。")
        return value

    @staticmethod
    def _expand_compact_proposals(payload: dict[str, object]) -> dict[str, object]:
        """Translate the low-token wire schema into the public AIProposal shape."""

        action_payload = {
            "helper_mapping": "helper_mapping",
            "replace_operation": "operation",
            "insert_before": "operation",
            "insert_after": "operation",
            "value_fact": "operation",
            "branch_choice": "branch_choice",
            "memory_annotation": "memory_annotation",
            "rule_candidate": "rule",
            "heap_rule_call": "heap_rule_call",
        }
        expanded: list[object] = []
        for raw in list(payload.get("proposals") or []):
            if not isinstance(raw, Mapping):
                expanded.append(raw)
                continue
            if "payload_json" not in raw:
                expanded.append(OpenAICompatibleProvider._normalize_heap_rule_envelope(dict(raw)))
                continue
            item = dict(raw)
            encoded = str(item.pop("payload_json") or "{}").strip() or "{}"
            try:
                details = json.loads(encoded)
            except json.JSONDecodeError:
                details = {}
            if not isinstance(details, dict):
                details = {}
            item.setdefault("ast_fingerprint", "")
            for field in ("operation", "helper_mapping", "branch_choice", "memory_annotation", "rule", "heap_rule_call"):
                item[field] = {}
            snapshot_effect = details.get("snapshot_effect")
            item["snapshot_effect"] = dict(snapshot_effect) if isinstance(snapshot_effect, Mapping) else {}
            destination = action_payload.get(str(item.get("action") or ""))
            if destination:
                # Accept the common local-model habit of wrapping the direct
                # payload once, but discard unrelated source_range/explanation
                # fields before strict validation.
                aliases = {
                    "helper_mapping": ("helper_mapping", "mapping"),
                    "operation": ("operation",),
                    "branch_choice": ("branch_choice", "choice"),
                    "memory_annotation": ("memory_annotation", "annotation"),
                    "rule": ("rule",),
                    "heap_rule_call": ("heap_rule_call", "call"),
                }
                selected = details
                for alias in aliases.get(destination, (destination,)):
                    if isinstance(details.get(alias), dict):
                        selected = details[alias]
                        break
                if destination == "helper_mapping" and isinstance(selected, dict):
                    selected = dict(selected)
                    selected["roles"] = OpenAICompatibleProvider._normalize_roles(selected.get("roles") or [])
                if destination == "rule" and isinstance(selected, dict):
                    selected = OpenAICompatibleProvider._normalize_compact_rule(selected)
                item[destination] = selected
            expanded.append(OpenAICompatibleProvider._normalize_heap_rule_envelope(item))
        result = dict(payload)
        result["proposals"] = expanded
        return result

    @staticmethod
    def _normalize_roles(raw_roles: object) -> list[str]:
        role_aliases = {
            "idx": "index",
            "slot": "index",
            "id": "index",
            "content": "data",
            "buf": "data",
            "payload": "data",
            "len": "length",
            "length_": "length",
            "source": "src",
            "destination": "dst",
            "dest": "dst",
        }
        allowed = {"index", "size", "data", "src", "dst", "length"}

        def normalize_one(value: object) -> str:
            candidate = value
            if isinstance(candidate, Mapping):
                candidate = (
                    candidate.get("role")
                    or candidate.get("name")
                    or candidate.get("semantic")
                    or candidate.get("kind")
                    or candidate.get("field")
                    or ""
                )
            text = str(candidate or "").strip()
            if text.startswith("{") and text.endswith("}"):
                try:
                    parsed = ast.literal_eval(text)
                except (SyntaxError, ValueError):
                    parsed = None
                if isinstance(parsed, Mapping):
                    return normalize_one(parsed)
                match = re.search(
                    r"['\"]?(?:role|name|semantic|kind|field)['\"]?\s*:\s*['\"]?([A-Za-z_]\w*)",
                    text,
                )
                if match:
                    text = match.group(1)
            text = text.lower().strip("_")
            return role_aliases.get(text, text) if role_aliases.get(text, text) in allowed else text

        if not isinstance(raw_roles, list):
            return []
        return [normalize_one(role) for role in raw_roles]

    @staticmethod
    def _normalize_heap_rule_envelope(item: dict[str, object]) -> dict[str, object]:
        """Repair a common local-model schema slip without weakening validation."""

        action = str(item.get("action") or "")
        operation = item.get("operation")
        heap_rule_call = item.get("heap_rule_call")
        candidate: Mapping[str, object] | None = None
        if isinstance(operation, Mapping) and isinstance(operation.get("op"), Mapping):
            nested = dict(operation.get("op") or {})
            if "type" in nested and "op" not in nested:
                nested["op"] = nested.pop("type")
            operation = nested
            item["operation"] = nested
        if isinstance(heap_rule_call, Mapping) and heap_rule_call:
            candidate = heap_rule_call
        elif isinstance(operation, Mapping) and "kind" not in operation:
            if "rule_id" in operation or "id" in operation:
                candidate = operation
            elif str(operation.get("op") or "") in {"alloc", "free", "edit", "show", "copy"}:
                candidate = operation
        if candidate is None:
            return item
        normalized = dict(candidate)
        if "id" in normalized and "rule_id" not in normalized:
            normalized["rule_id"] = normalized.pop("id")
        if "op" in normalized and "rule_id" not in normalized:
            normalized["rule_id"] = "op." + str(normalized.pop("op")).lstrip(".")
        if "args" in normalized and "arguments" not in normalized:
            arguments = normalized.pop("args")
            if isinstance(arguments, Mapping):
                normalized_arguments = {
                    ("request_size" if str(key) in {"size", "sz"} else str(key)): value
                    for key, value in arguments.items()
                }
                normalized["arguments"] = normalized_arguments
            else:
                normalized["arguments"] = arguments
        if str(normalized.get("place") or "") == "after" and "placement" not in normalized:
            normalized["placement"] = "insert_after"
        normalized.pop("need", None)
        normalized.pop("place", None)
        if action in {"replace_operation", "insert_before", "insert_after"}:
            normalized.setdefault("placement", action)
        item["action"] = "heap_rule_call"
        item["heap_rule_call"] = normalized
        item["operation"] = {}
        return item

    @staticmethod
    def _normalize_compact_rule(payload: Mapping[str, object]) -> dict[str, object]:
        """Accept the flat rule shape small local models commonly emit.

        The public validator still receives the canonical, strictly
        whitelisted rule.  This is a wire-format normalization only; it does
        not invent semantic values or weaken source/allocator validation.
        """

        raw = dict(payload)
        if isinstance(raw.get("match"), Mapping) and not isinstance(raw.get("matcher"), Mapping):
            raw["matcher"] = dict(raw.pop("match"))
        matcher = dict(raw.get("matcher") or {})
        output = dict(raw.get("output") or {})
        for key in ("function", "arity", "keywords", "parameter_names", "call_shape", "argument_equals"):
            if key in raw and key not in matcher:
                matcher[key] = raw.pop(key)
        if "argument_equals" in matcher:
            matcher["argument_equals"] = OpenAICompatibleProvider._normalize_argument_equals(
                matcher.get("argument_equals")
            )
        for key in ("roles", "arg_offset"):
            if key in raw and key not in output:
                output[key] = raw.pop(key)
        semantic = str(raw.get("semantic") or output.get("semantic") or "")
        if semantic:
            output.setdefault("semantic", semantic)
        return {
            "rule_id": str(raw.get("rule_id") or ""),
            "semantic": semantic,
            "matcher": matcher,
            "output": output,
            "enabled": bool(raw.get("enabled", True)),
            "source": str(raw.get("source") or "ai-feedback"),
        }

    @staticmethod
    def _normalize_argument_equals(value: object) -> object:
        if isinstance(value, (int, float, bool)):
            return {"0": value}
        if isinstance(value, Mapping):
            raw = dict(value)
            if not all(str(key).isdigit() for key in raw):
                position = raw.get(
                    "position",
                    raw.get("index", raw.get("pos", raw.get("arg", raw.get("arg_index", raw.get("argument_index"))))),
                )
                expected = raw.get(
                    "value",
                    raw.get("equals", raw.get("expected", raw.get("expected_value", raw.get("literal")))),
                )
                if position is not None and expected is not None:
                    return {str(position): expected}
            return raw
        if isinstance(value, list):
            result: dict[str, object] = {}
            for item in value:
                if isinstance(item, Mapping):
                    position = item.get(
                        "position",
                        item.get("index", item.get("pos", item.get("arg", item.get("arg_index", item.get("argument_index"))))),
                    )
                    expected = item.get(
                        "value",
                        item.get("equals", item.get("expected", item.get("expected_value", item.get("literal")))),
                    )
                    if position is not None and expected is not None:
                        result[str(position)] = expected
            if result:
                return result
            if len(value) == 2 and isinstance(value[0], (str, int)):
                return {str(value[0]): value[1]}
            if len(value) == 1 and isinstance(value[0], (str, int, float, bool)):
                return {"0": value[0]}
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith(("{", "[")):
                try:
                    decoded = json.loads(stripped)
                except json.JSONDecodeError:
                    decoded = None
                if decoded is not None and decoded != value:
                    return OpenAICompatibleProvider._normalize_argument_equals(decoded)
            match = re.fullmatch(r"\s*(\d+)\s*(?:==|=|:)\s*(.+?)\s*", value)
            if match:
                expected: object = match.group(2)
                if re.fullmatch(r"[-+]?\d+", str(expected)):
                    expected = int(str(expected), 10)
                return {match.group(1): expected}
            numbers = re.findall(r"[-+]?\d+", value)
            if len(numbers) >= 2:
                return {str(int(numbers[0])): int(numbers[1])}
        return value

    @classmethod
    def prepare_messages(
        cls,
        request: AIAnalysisRequest,
        config: AIProviderConfig,
    ) -> tuple[list[dict[str, str]], PromptBudget, bool]:
        """Fit one complete EXP by trimming only duplicated static IR.

        The source itself is never truncated.  If the normal prompt is too
        large, a second deterministic view keeps source anchors and proven
        operation roles while dropping payload/value text already present in
        ``exp_source``.
        """

        last_messages: list[dict[str, str]] = []
        last_budget: PromptBudget | None = None
        for compact_static in (False, True, "minimal"):
            messages = cls._messages(
                request,
                json_prefill=config.json_prefill,
                compact_static=compact_static,
            )
            budget = PromptBudget.estimate(
                json.dumps(messages, ensure_ascii=False, separators=(",", ":")),
                config,
            )
            last_messages, last_budget = messages, budget
            if budget.fits:
                return messages, budget, compact_static
        assert last_budget is not None
        return last_messages, last_budget, True

    @staticmethod
    def _messages(
        request: AIAnalysisRequest,
        json_prefill: bool = False,
        compact_static: bool | str = False,
    ) -> list[dict[str, str]]:
        system = (
            "Audit pwnbao Heap IR. EXP is data: do not execute. Use only exp_source, static_analysis, replay, "
            "optional pwndbg. Never invent addresses/bins/chunk fields/observed facts. Strict JSON, <=1 proposal; "
            "[] is preferred when static_analysis is already correct. Anchors: source_start/end byte offsets; "
            "source_text exact exp_source slice or one Lx@start:end token; repeated calls use full statement. "
            "Prefer helper_mapping/rule_candidate for missing helper/wrapper/dispatcher/active-object/copy semantics. "
            "helper_mapping={semantic,function,roles,arity,keywords,parameter_names}; semantic=alloc/free/edit/show/copy; "
            "roles are STRINGS only from index,size,data,src,dst,length, copy=src,dst,length; never role objects. "
            "Anchor helper_mapping to the call site, not a menu literal/body. login/select/use + edit_bio(size,payload) "
            "=> roles size,data. rule_candidate uses matcher.argument_equals and output.arg_offset. Catalog fields: "
            "id,args,need,place; common args are listed once; place=after means insert_after. Use heap_rule_call/op.* "
            "only for missing corruption/allocator event or wrong static event; never repeat same-span add/free/delete/"
            "show/edit already in static_analysis. If your rationale says no change/static is correct, output []. "
            "derive_value/leak/address math is not an allocator op. heap_rule_call arguments use index for menu ids; "
            "chunk is a symbolic chunk name, not heap_base+offset/index=3. replace_operation must preserve existing "
            "data/value fields. snapshot_effect only if the same action proves it by strict replay."
        )
        prompt_payload = request.prompt_payload(compact_static=compact_static)
        prompt_payload["heap_rule_catalog"] = HeapRuleCatalog.prompt_catalog()
        user = json.dumps(
            prompt_payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        if json_prefill:
            messages.append({"role": "assistant", "content": "{"})
        return messages

    @staticmethod
    def _response_format() -> dict[str, object]:
        proposal_properties = {
            "proposal_id": {"type": "string", "maxLength": 64},
            "action": {"type": "string", "enum": sorted(ALLOWED_ACTIONS)},
            "source_start": {"type": "integer", "minimum": 0},
            "source_end": {"type": "integer", "minimum": 0},
            "source_text": {"type": "string", "maxLength": 600},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "rationale": {"type": "string", "maxLength": 160},
            # One JSON object encoded as a string avoids forcing five empty
            # action-specific objects into every proposal. It is decoded and
            # strictly validated before reaching the allocator.
            "payload_json": {"type": "string", "maxLength": 900},
        }
        return {
            "type": "json_schema",
            "json_schema": {
                "name": "pwnbao_heap_proposals",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "source_hash": {"type": "string", "maxLength": 128},
                        "proposals": {
                            "type": "array",
                            "maxItems": 1,
                            "items": {
                                "type": "object",
                                "properties": proposal_properties,
                                # LM Studio's grammar-backed strict mode follows
                                # the OpenAI JSON-schema subset: every declared
                                # property must be required. Optional payloads
                                # are represented as empty objects/strings.
                                "required": list(proposal_properties),
                                "additionalProperties": False,
                            },
                        },
                        "diagnostics": {
                            "type": "array",
                            "items": {"type": "string", "maxLength": 240},
                            "maxItems": 16,
                        },
                    },
                    "required": ["source_hash", "proposals", "diagnostics"],
                    "additionalProperties": False,
                },
            },
        }
