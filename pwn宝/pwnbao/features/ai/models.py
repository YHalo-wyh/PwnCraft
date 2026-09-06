from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Mapping


AI_SCHEMA_VERSION = 1
AI_PROMPT_VERSION = "pwnbao-heap-ai-v10-negative-rules"


@dataclass(frozen=True)
class AIProviderConfig:
    base_url: str = "http://127.0.0.1:1234/v1"
    model: str = "qwen3-coder-30b-a3b-instruct"
    api_token: str = ""
    # Qwen3-Coder-30B-A3B-Instruct-Q4_K_M is an MoE model (about 3B active
    # parameters) and is markedly faster than the previously selected dense
    # 27B model even though both require CPU/GPU mixed loading on an 8 GB GPU.
    timeout: float = 180.0
    temperature: float = 0.1
    max_tokens: int = 512
    analysis_mode: str = "manual"
    context_budget_tokens: int = 4096
    max_input_tokens: int = 3584
    # Assistant JSON prefill keeps reasoning-heavy Qwen models in their final
    # answer channel; LM Studio still enforces the response schema.
    json_prefill: bool = True

    def normalized_base_url(self) -> str:
        value = (self.base_url or "http://127.0.0.1:1234/v1").strip().rstrip("/")
        return value or "http://127.0.0.1:1234/v1"

    def public_dict(self) -> dict[str, object]:
        return {
            "base_url": self.normalized_base_url(),
            "model": self.model,
            "timeout": self.timeout,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "analysis_mode": self.analysis_mode,
            "context_budget_tokens": self.context_budget_tokens,
            "max_input_tokens": self.max_input_tokens,
            "json_prefill": self.json_prefill,
        }


@dataclass(frozen=True)
class PromptBudget:
    """Conservative, tokenizer-free budget for a local chat request.

    PwnCraft intentionally does not add a model tokenizer dependency.  JSON-heavy
    prompts are estimated at three UTF-8 bytes per token and include a small
    framing allowance.  The estimate errs on the safe side: an over-budget EXP
    is rejected instead of being silently truncated.
    """

    estimated_input_tokens: int
    context_budget_tokens: int
    reserved_output_tokens: int
    max_input_tokens: int
    encoded_bytes: int
    fits: bool
    diagnostic: str = ""

    @classmethod
    def estimate(cls, prompt_text: str, config: AIProviderConfig) -> "PromptBudget":
        encoded_bytes = len((prompt_text or "").encode("utf-8", errors="replace"))
        # Chat roles, the response grammar and message framing also consume
        # context. Keep 160 tokens aside rather than pretending the payload is
        # the complete request.
        estimated = max(1, math.ceil(encoded_bytes / 3.0) + 160)
        context = max(1024, int(config.context_budget_tokens))
        output = max(256, int(config.max_tokens))
        configured_input = max(256, int(config.max_input_tokens))
        available_input = max(0, min(configured_input, context - output))
        fits = estimated <= available_input
        if fits:
            diagnostic = f"预计输入 {estimated} tokens / 可用 {available_input}"
        else:
            diagnostic = (
                f"预计输入 {estimated} tokens，超过当前可用 {available_input}；"
                "请精简 EXP/本题指令，或在 LM Studio 和 PwnCraft中同时提高上下文。"
            )
        return cls(estimated, context, output, configured_input, encoded_bytes, fits, diagnostic)


@dataclass(frozen=True)
class AIAnalysisRequest:
    generation: int
    source_hash: str
    source: str
    allocator: dict[str, object]
    static_result: dict[str, object]
    instruction: str = ""
    learned_rules: tuple[dict[str, object], ...] = ()
    examples: tuple[dict[str, object], ...] = ()
    current_snapshot: dict[str, object] = field(default_factory=dict)
    observed_heap: dict[str, object] = field(default_factory=dict)
    observed_diff: dict[str, object] = field(default_factory=dict)
    prompt_version: str = AI_PROMPT_VERSION
    schema_version: int = AI_SCHEMA_VERSION

    @classmethod
    def build(
        cls,
        generation: int,
        source: str,
        allocator: Mapping[str, object],
        static_result: Mapping[str, object],
        *,
        instruction: str = "",
        learned_rules: tuple[dict[str, object], ...] = (),
        examples: tuple[dict[str, object], ...] = (),
        current_snapshot: Mapping[str, object] | None = None,
        observed_heap: Mapping[str, object] | None = None,
        observed_diff: Mapping[str, object] | None = None,
    ) -> "AIAnalysisRequest":
        digest = hashlib.sha256((source or "").encode("utf-8", errors="replace")).hexdigest()
        return cls(
            generation=generation,
            source_hash=digest,
            source=source or "",
            allocator=dict(allocator),
            static_result=dict(static_result),
            instruction=instruction.strip(),
            learned_rules=learned_rules,
            examples=examples,
            current_snapshot=dict(current_snapshot or {}),
            observed_heap=dict(observed_heap or {}),
            observed_diff=dict(observed_diff or {}),
        )

    def prompt_payload(self, *, compact_static: bool | str = False) -> dict[str, object]:
        compact_rules = _compact_rules(self.learned_rules)
        payload = {
            "schema_version": self.schema_version,
            "source_hash": self.source_hash,
            "allocator": self.allocator,
            "instruction": self.instruction,
            # Keep the complete EXP, but do not send a second, verbose copy of
            # it through operation notes, source_text and expression metadata.
            # This is what makes a normal 100-200 line exploit fit a 6K local
            # context without silently truncating source code.
            "static_analysis": _compact_static_result(
                self.static_result,
                lean=bool(compact_static),
                minimal=compact_static == "minimal",
            ),
            "learned_rules": compact_rules,
            # Exact rules are stronger and cheaper than repeating their
            # originating feedback. Few-shot examples are used only when no
            # deterministic learned rule is available for the request.
            "reviewed_examples": [] if compact_rules else _compact_examples(self.examples),
            "exp_source": self.source,
        }
        if self.current_snapshot:
            payload["current_snapshot"] = _compact_heap_snapshot(
                self.current_snapshot,
                minimal=compact_static == "minimal",
            )
        if self.observed_heap:
            payload["pwndbg_observed"] = _bounded_value(self.observed_heap, 240)
        if self.observed_diff:
            payload["simulation_diff"] = _bounded_value(self.observed_diff, 300)
        return payload


def _short_text(value: object, limit: int = 240) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "..."


def _bounded_value(value: object, limit: int = 240) -> object:
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    if isinstance(value, str):
        return _short_text(value, limit)
    if isinstance(value, Mapping):
        return {
            _short_text(key, 80): _bounded_value(item, limit)
            for key, item in list(value.items())[:32]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded_value(item, limit) for item in list(value)[:32]]
    return _short_text(repr(value), limit)


def _compact_heap_snapshot(raw: Mapping[str, object], *, minimal: bool = False) -> dict[str, object]:
    """Keep allocator facts while removing repeated per-chunk JSON keys."""

    result: dict[str, object] = {
        "step": raw.get("step", 0),
        "aborted": bool(raw.get("aborted", False)),
    }
    chunks = raw.get("chunks") or {}
    if isinstance(chunks, Mapping):
        items = list(chunks.items())
        known_chunk_ids = {str(chunk_id) for chunk_id, _value in items}
        grouped: dict[tuple[str, ...], list[str]] = {}
        pointer_rows: list[str] = []
        for chunk_id, value in items[:64]:
            if not isinstance(value, Mapping):
                continue
            fields = (
                ("addr", value.get("address")),
                ("user", value.get("user_address")),
                ("size", value.get("chunk_size")),
                ("state", value.get("lifecycle")),
                ("bin", value.get("bin_location")),
                ("prov", value.get("provenance")),
            )
            normalized_fields = []
            for name, field_value in fields:
                text_value = str(field_value or "")
                if "+?<" in text_value:
                    text_value = "unknown-layout"
                normalized_fields.append((name, text_value if field_value not in (None, "") else field_value))
            fact_parts = tuple(
                f"{name}={_short_text(field_value, 80)}"
                for name, field_value in normalized_fields
                if field_value not in (None, "")
            )
            grouped.setdefault(fact_parts, []).append(str(chunk_id))
            unusual_pointers: list[str] = []
            for name in ("fd", "bk"):
                pointer = str(value.get(name) or "").strip()
                target = pointer.split(" ", 1)[0]
                if pointer and target not in known_chunk_ids and target not in {"NULL", "main_arena"}:
                    unusual_pointers.append(f"{name}={_short_text(pointer, 100)}")
            if unusual_pointers:
                pointer_rows.append(f"{chunk_id} " + " ".join(unusual_pointers))
        rows = [
            _short_text(f"{','.join(chunk_ids)} {' '.join(facts)}".strip(), 500)
            for facts, chunk_ids in grouped.items()
        ]
        result["chunk_rows"] = rows
        if pointer_rows:
            result["nonstandard_pointer_rows"] = pointer_rows[:16]
        if len(items) > len(rows):
            result["grouped_chunk_count"] = len(items)
        if minimal and len(rows) > 8:
            result["chunk_rows"] = rows[:8]
            result["omitted_chunk_rows"] = len(rows) - 8
    bins = raw.get("bins") or {}
    if isinstance(bins, Mapping):
        bin_rows: list[str] = []
        for bin_name, value in list(bins.items())[:8]:
            if isinstance(value, Mapping):
                for size, chain in list(value.items())[:16]:
                    nodes = ",".join(str(item) for item in list(chain)[:16]) if isinstance(chain, (list, tuple)) else str(chain)
                    bin_rows.append(_short_text(f"{bin_name}[{size}]={nodes}", 300))
            elif isinstance(value, (list, tuple)) and value:
                bin_rows.append(_short_text(f"{bin_name}=" + ",".join(str(item) for item in value[:16]), 300))
        if bin_rows:
            result["bin_rows"] = bin_rows
    warnings = raw.get("warnings") or []
    if isinstance(warnings, (list, tuple)) and warnings:
        result["warnings"] = [_short_text(item, 80) for item in warnings[:16]]
    return result


def _compact_examples(examples: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    compact: list[dict[str, object]] = []
    for raw in list(examples)[:1]:
        if not isinstance(raw, Mapping):
            continue
        item: dict[str, object] = {}
        for key in ("feedback_id", "decision", "similarity"):
            if key in raw:
                item[key] = _bounded_value(raw[key], 120)
        item["source_fragment"] = _short_text(raw.get("source_fragment"), 260)
        proposal = raw.get("proposal") or {}
        final_value = raw.get("final_value") or {}
        if isinstance(proposal, Mapping):
            item["proposal"] = _compact_feedback_value(proposal)
        if isinstance(final_value, Mapping) and final_value != proposal:
            item["expected"] = _compact_feedback_value(final_value)
        compact.append(item)
    return compact


def _compact_feedback_value(raw: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key in ("action", "source_text"):
        if raw.get(key) not in (None, ""):
            result[key] = _bounded_value(raw[key], 180)
    for key in ("operation", "helper_mapping", "branch_choice", "memory_annotation", "rule"):
        value = raw.get(key)
        if isinstance(value, Mapping) and value:
            result[key] = _bounded_value(value, 160)
            break
    snapshot_effect = raw.get("snapshot_effect")
    if isinstance(snapshot_effect, Mapping) and snapshot_effect:
        result["snapshot_effect"] = _bounded_value(snapshot_effect, 180)
    return result


def _compact_rules(rules: tuple[dict[str, object], ...]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for raw in list(rules)[:16]:
        if not isinstance(raw, Mapping):
            continue
        matcher = raw.get("matcher") or {}
        output = raw.get("output") or {}
        item = {
            "rule_id": _short_text(raw.get("rule_id"), 80),
            "semantic": _short_text(raw.get("semantic"), 32),
            "matcher": {
                key: _bounded_value(value, 100)
                for key, value in dict(matcher).items()
                if key in {"function", "arity", "keywords", "parameter_names", "call_shape", "argument_equals"}
            } if isinstance(matcher, Mapping) else {},
            "output": {
                key: _bounded_value(value, 100)
                for key, value in dict(output).items()
                if key in {"roles", "semantic", "arg_offset"}
            } if isinstance(output, Mapping) else {},
        }
        result.append(item)
    return result


def _compact_static_result(
    raw: Mapping[str, object],
    *,
    lean: bool = False,
    minimal: bool = False,
) -> dict[str, object]:
    """Build the prompt-only Heap IR used by the local model.

    The in-memory ``HeapAnalysisResult`` remains lossless.  This view removes
    generated notes and duplicates, joins each operation with its source
    binding, and folds loop iterations sharing one source range.  Key names
    remain descriptive so a general local model does not need a private
    decoder vocabulary.
    """

    operations = list(raw.get("operations") or [])
    bindings = list(raw.get("bindings") or [])
    entries: list[dict[str, object]] = []
    duplicate_meta = {"parse_confidence", "source", "expression", "function"}
    for index, operation_raw in enumerate(operations[:1024]):
        if not isinstance(operation_raw, Mapping):
            continue
        binding_raw = bindings[index] if index < len(bindings) and isinstance(bindings[index], Mapping) else {}
        operation = dict(operation_raw)
        binding = dict(binding_raw)
        entry: dict[str, object] = {
            "step": index + 1,
            "kind": _short_text(operation.get("kind"), 48),
        }
        line = int(binding.get("line") or 0)
        start = int(binding.get("start") or 0)
        end = int(binding.get("end") or 0)
        if line:
            entry["line"] = line
        if end > start >= 0:
            entry["span"] = [start, end]
        field_map = {
            "chunk": "chunk",
            "index": "index",
            "request_size": "size",
            "data": "data",
            "field": "field",
            "value": "value",
            "target": "target",
            "fd_storage": "fd_storage",
        }
        for source_key, output_key in field_map.items():
            value = operation.get(source_key)
            if value not in (None, ""):
                entry[output_key] = _bounded_value(value, 300 if output_key in {"data", "value"} else 160)
        count = int(operation.get("count") or 1)
        if count != 1:
            entry["count"] = count
        loop_env = binding.get("loop_env") or []
        if isinstance(loop_env, Mapping):
            loop = dict(loop_env)
        else:
            try:
                loop = {str(key): _bounded_value(value, 80) for key, value in loop_env}
            except (TypeError, ValueError):
                loop = {}
        if loop:
            entry["loop"] = loop
        confidence = str(binding.get("confidence") or "confirmed")
        if confidence != "confirmed":
            entry["confidence"] = confidence
        fingerprint = str(binding.get("fingerprint") or "")
        if fingerprint and confidence != "confirmed":
            entry["fingerprint"] = fingerprint[:40]
        meta_raw = operation.get("meta") or {}
        if isinstance(meta_raw, Mapping):
            meta = {
                str(key): _bounded_value(value, 240)
                for key, value in list(meta_raw.items())[:32]
                if key not in duplicate_meta and value not in (None, "")
            }
            if meta:
                entry["meta"] = meta
        entries.append(entry)

    grouped: list[dict[str, object]] = []
    for entry in entries:
        same_site = bool(
            grouped
            and entry.get("kind") == grouped[-1].get("kind")
            and entry.get("line") == grouped[-1].get("line")
            and entry.get("span") == grouped[-1].get("span")
        )
        if not same_site:
            grouped.append(dict(entry))
            continue
        group = grouped[-1]
        if "iterations" not in group:
            first = {
                key: value
                for key, value in group.items()
                if key not in {"step", "kind", "line", "span"}
            }
            first_step = int(group.pop("step"))
            for key in first:
                group.pop(key, None)
            group["steps"] = [first_step]
            group["iterations"] = [first]
        iteration = {
            key: value
            for key, value in entry.items()
            if key not in {"step", "kind", "line", "span"}
        }
        group["steps"].append(int(entry["step"]))
        group["iterations"].append(iteration)

    timeline = [_compact_timeline_line(item, lean=lean) for item in grouped]
    if minimal:
        timeline = [
            " ".join(
                part
                for part in (
                    f"L{int(item.get('line') or 0)}" if int(item.get("line") or 0) else "L?",
                    _short_text(item.get("kind"), 24),
                )
                if part
            )
            for item in grouped
        ]
        timeline, repeated = _dedupe_minimal_timeline(timeline)
    result: dict[str, object] = {
        # A line-oriented IR is substantially cheaper for a CPU/GPU mixed
        # local coder model than repeating dozens of JSON property names. The complete
        # structured result remains in memory and every line/span needed for
        # a proposal anchor is preserved here.
        "timeline": timeline,
    }
    if minimal and repeated:
        result["timeline_repeats"] = repeated[:64]
    if not lean or not bool(raw.get("valid", True)):
        result["valid"] = bool(raw.get("valid", True))
    if not lean:
        result["operation_count"] = len(operations)
    branches = raw.get("branches") or []
    if isinstance(branches, list) and branches:
        result["branches"] = [_bounded_value(item, 240) for item in branches[:32]]
    diagnostics = raw.get("diagnostics") or []
    if isinstance(diagnostics, list) and diagnostics:
        if lean:
            result["diagnostics"] = [
                {
                    "severity": str(item.get("severity") or ""),
                    "code": str(item.get("code") or ""),
                    "line": int(item.get("line") or 0),
                }
                for item in diagnostics[:16]
                if isinstance(item, Mapping) and str(item.get("severity") or "") in {"error", "warning"}
            ]
        else:
            result["diagnostics"] = [_bounded_value(item, 300) for item in diagnostics[:32]]
    symbols = raw.get("symbols") or {}
    if isinstance(symbols, Mapping) and not lean:
        compact_symbols = {
            _short_text(key, 80): _bounded_value(value, 120)
            for key, value in list(symbols.items())[:48]
            if isinstance(value, (str, int, float, bool, type(None)))
        }
        if compact_symbols:
            result["symbols"] = compact_symbols
    if not bool(raw.get("valid", True)):
        last_valid = list(raw.get("last_valid_operations") or [])
        if last_valid:
            result["last_valid_operation_count"] = len(last_valid)
            result["last_valid_operations"] = [
                {
                    key: _bounded_value(value, 200)
                    for key, value in dict(item).items()
                    if key in {"kind", "chunk", "index", "request_size", "data", "value", "target"}
                    and value not in (None, "")
                }
                for item in last_valid[:128]
                if isinstance(item, Mapping)
            ]
    return result


def _dedupe_minimal_timeline(timeline: list[str]) -> tuple[list[str], list[str]]:
    seen: dict[str, int] = {}
    result: list[str] = []
    for line in timeline:
        seen[line] = seen.get(line, 0) + 1
        if seen[line] == 1:
            result.append(line)
    repeated = [f"{line} ×{count}" for line, count in seen.items() if count > 1]
    return result, repeated


def _compact_timeline_line(entry: Mapping[str, object], *, lean: bool = False) -> str:
    kind = _short_text(entry.get("kind"), 48)
    line = int(entry.get("line") or 0)
    span = entry.get("span") or []
    if isinstance(span, (list, tuple)) and len(span) == 2:
        site = f"L{line}@{span[0]}:{span[1]}"
    else:
        site = f"L{line}" if line else "L?"

    ignored = {"step", "steps", "kind", "line", "span", "iterations"}

    def flatten(item: Mapping[str, object]) -> dict[str, str]:
        values: dict[str, str] = {}
        for key, value in item.items():
            if key in ignored or value in (None, "", [], {}):
                continue
            # Budget fallback keeps the complete EXP and every source anchor,
            # but removes values already visible in the source.  Proven
            # semantic fields remain, so the model can still compare the AST
            # result without receiving a second near-copy of a long payload.
            if lean and key not in {"chunk", "index", "size", "target", "meta"}:
                continue
            if key == "loop" and isinstance(value, Mapping):
                values["loop"] = ",".join(f"{name}={_short_text(loop_value, 40)}" for name, loop_value in value.items())
            elif key == "meta" and isinstance(value, Mapping):
                meta_keys = (
                    ("result_var", "src", "dst", "length", "branch_id")
                    if lean else
                    (
                        "result_var", "dependencies", "observed_bytes", "byte_width",
                        "src", "dst", "length", "prev_size", "size", "fd", "bk",
                        "provenance", "analysis_status", "branch_id",
                    )
                )
                for meta_key in meta_keys:
                    if value.get(meta_key) not in (None, ""):
                        values[meta_key] = _short_text(value[meta_key], 100)
            elif key not in {"fingerprint"}:
                values[str(key)] = _short_text(value, 120 if key in {"data", "value"} else 80)
        return values

    iterations = entry.get("iterations") or []
    if isinstance(iterations, list) and iterations:
        first = flatten(iterations[0]) if isinstance(iterations[0], Mapping) else {}
        last = flatten(iterations[-1]) if isinstance(iterations[-1], Mapping) else {}
        merged: list[str] = []
        for key in dict.fromkeys([*first, *last]):
            left, right = first.get(key, ""), last.get(key, "")
            merged.append(f"{key}={left}" if left == right else f"{key}={left}..{right}")
        steps = list(entry.get("steps") or [])
        step_text = f"{steps[0]}-{steps[-1]}" if steps else "?"
        return " ".join(
            part
            for part in (("" if lean else step_text), site, kind, f"repeat={len(iterations)}", *merged)
            if part
        )

    fields = flatten(entry)
    return " ".join(
        part
        for part in (
            ("" if lean else str(entry.get("step") or "?")), site, kind,
            *(f"{key}={value}" for key, value in fields.items()),
        )
        if part
    )


@dataclass(frozen=True)
class AIProposal:
    proposal_id: str
    action: str
    source_start: int
    source_end: int
    source_text: str
    ast_fingerprint: str = ""
    confidence: float = 0.0
    rationale: str = ""
    operation: dict[str, object] = field(default_factory=dict)
    helper_mapping: dict[str, object] = field(default_factory=dict)
    branch_choice: dict[str, object] = field(default_factory=dict)
    memory_annotation: dict[str, object] = field(default_factory=dict)
    rule: dict[str, object] = field(default_factory=dict)
    heap_rule_call: dict[str, object] = field(default_factory=dict)
    snapshot_effect: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "proposal_id": self.proposal_id,
            "action": self.action,
            "source_start": self.source_start,
            "source_end": self.source_end,
            "source_text": self.source_text,
            "ast_fingerprint": self.ast_fingerprint,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "operation": dict(self.operation),
            "helper_mapping": dict(self.helper_mapping),
            "branch_choice": dict(self.branch_choice),
            "memory_annotation": dict(self.memory_annotation),
            "rule": dict(self.rule),
            "heap_rule_call": dict(self.heap_rule_call),
            "snapshot_effect": dict(self.snapshot_effect),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "AIProposal":
        return cls(
            proposal_id=str(payload.get("proposal_id") or ""),
            action=str(payload.get("action") or ""),
            source_start=int(payload.get("source_start") or 0),
            source_end=int(payload.get("source_end") or 0),
            source_text=str(payload.get("source_text") or ""),
            ast_fingerprint=str(payload.get("ast_fingerprint") or ""),
            confidence=float(payload.get("confidence") or 0.0),
            rationale=str(payload.get("rationale") or ""),
            operation=dict(payload.get("operation") or {}),
            helper_mapping=dict(payload.get("helper_mapping") or {}),
            branch_choice=dict(payload.get("branch_choice") or {}),
            memory_annotation=dict(payload.get("memory_annotation") or {}),
            rule=dict(payload.get("rule") or {}),
            heap_rule_call=dict(payload.get("heap_rule_call") or {}),
            snapshot_effect=dict(payload.get("snapshot_effect") or {}),
        )

    def signature(self) -> str:
        canonical = {
            "action": self.action,
            "source_text": " ".join(self.source_text.split()),
            "operation": self.operation,
            "helper_mapping": self.helper_mapping,
            "branch_choice": self.branch_choice,
            "memory_annotation": self.memory_annotation,
            "rule": self.rule,
            "heap_rule_call": self.heap_rule_call,
            "snapshot_effect": self.snapshot_effect,
        }
        raw = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AIAnalysisResult:
    generation: int
    source_hash: str
    proposals: tuple[AIProposal, ...] = ()
    diagnostics: tuple[str, ...] = ()
    elapsed_ms: int = 0
    model: str = ""
    cached: bool = False
    prompt_version: str = AI_PROMPT_VERSION
    candidate_audit: tuple[dict[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "generation": self.generation,
            "source_hash": self.source_hash,
            "proposals": [item.to_dict() for item in self.proposals],
            "diagnostics": list(self.diagnostics),
            "elapsed_ms": self.elapsed_ms,
            "model": self.model,
            "cached": self.cached,
            "prompt_version": self.prompt_version,
            "candidate_audit": [dict(item) for item in self.candidate_audit],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "AIAnalysisResult":
        return cls(
            generation=int(payload.get("generation") or 0),
            source_hash=str(payload.get("source_hash") or ""),
            proposals=tuple(AIProposal.from_dict(item) for item in list(payload.get("proposals") or []) if isinstance(item, Mapping)),
            diagnostics=tuple(str(item) for item in list(payload.get("diagnostics") or [])),
            elapsed_ms=int(payload.get("elapsed_ms") or 0),
            model=str(payload.get("model") or ""),
            cached=bool(payload.get("cached", False)),
            prompt_version=str(payload.get("prompt_version") or AI_PROMPT_VERSION),
            candidate_audit=tuple(
                dict(item)
                for item in list(payload.get("candidate_audit") or [])[:4]
                if isinstance(item, Mapping)
            ),
        )


@dataclass(frozen=True)
class FeedbackRecord:
    feedback_id: str
    source_hash: str
    source_fragment: str
    decision: str  # accepted | modified | rejected
    proposal: dict[str, object]
    final_value: dict[str, object] = field(default_factory=dict)
    model: str = ""
    prompt_version: str = AI_PROMPT_VERSION
    created_at: str = ""


@dataclass(frozen=True)
class LearnedRule:
    rule_id: str
    semantic: str
    matcher: dict[str, object]
    output: dict[str, object]
    enabled: bool = True
    accept_count: int = 1
    reject_count: int = 0
    source: str = "ai-feedback"
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "semantic": self.semantic,
            "matcher": dict(self.matcher),
            "output": dict(self.output),
            "enabled": self.enabled,
            "accept_count": self.accept_count,
            "reject_count": self.reject_count,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "LearnedRule":
        return cls(
            rule_id=str(payload.get("rule_id") or ""),
            semantic=str(payload.get("semantic") or ""),
            matcher=dict(payload.get("matcher") or {}),
            output=dict(payload.get("output") or {}),
            enabled=bool(payload.get("enabled", True)),
            accept_count=int(payload.get("accept_count") or 1),
            reject_count=int(payload.get("reject_count") or 0),
            source=str(payload.get("source") or "ai-feedback"),
            created_at=str(payload.get("created_at") or ""),
            updated_at=str(payload.get("updated_at") or ""),
        )
