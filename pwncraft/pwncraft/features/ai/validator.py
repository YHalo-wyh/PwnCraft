from __future__ import annotations

import ast
import hashlib
import re
from typing import Mapping

from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwncraft.features.heapviz.validation import validate_operation

from .models import AIProposal
from .rule_catalog import HeapRuleCatalog


ALLOWED_ACTIONS = {
    "helper_mapping",
    "replace_operation",
    "insert_before",
    "insert_after",
    "ignore_operation",
    "branch_choice",
    "value_fact",
    "memory_annotation",
    "rule_candidate",
    "heap_rule_call",
}
ALLOWED_SEMANTICS = {"alloc", "free", "edit", "show", "copy"}
ALLOWED_ROLES = {"index", "size", "data", "src", "dst", "length"}
PROPOSAL_FIELDS = {
    "proposal_id", "action", "source_start", "source_end", "source_text",
    "ast_fingerprint", "confidence", "rationale", "operation",
    "helper_mapping", "branch_choice", "memory_annotation", "rule", "snapshot_effect",
    "heap_rule_call",
}
AI_OPERATION_META_FIELDS = {
    "function", "result_var", "expression", "dependencies", "source_kind", "source",
    "provenance", "byte_width", "endian", "slice_start", "slice_end", "shift", "mask",
    "src", "dst", "src_chunk", "dst_chunk", "length", "field", "value", "offset", "fd", "bk",
    "address", "main_arena_offset", "setcontext_offset", "role", "fd_storage", "size",
    "prev_size", "bin", "start_index", "analysis_status", "branch_id",
}


def validate_ai_response(payload: Mapping[str, object], source: str, expected_hash: str) -> tuple[tuple[AIProposal, ...], tuple[str, ...]]:
    diagnostics: list[str] = []
    response_hash = str(payload.get("source_hash") or "")
    if response_hash != expected_hash:
        return (), ("AI response source_hash 与当前 EXP 不匹配，已丢弃。",)
    raw_proposals = payload.get("proposals") or []
    if not isinstance(raw_proposals, list):
        return (), ("AI response proposals 必须是数组。",)
    result: list[AIProposal] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_proposals[:32]):
        if not isinstance(raw, Mapping):
            diagnostics.append(f"候选 {index + 1}: 不是 JSON 对象。")
            continue
        try:
            proposal = _validate_proposal(raw, source, index)
        except (TypeError, ValueError, KeyError) as error:
            diagnostics.append(f"候选 {index + 1}: {error}")
            continue
        if proposal.proposal_id in seen:
            diagnostics.append(f"候选 {index + 1}: proposal_id 重复。")
            continue
        seen.add(proposal.proposal_id)
        result.append(proposal)
    if len(raw_proposals) > 32:
        diagnostics.append("AI 候选超过 32 条，多余部分已丢弃。")
    raw_diagnostics = payload.get("diagnostics") or []
    if isinstance(raw_diagnostics, list):
        diagnostics.extend(str(item)[:500] for item in raw_diagnostics[:32])
    return tuple(result), tuple(diagnostics)


def _validate_proposal(raw: Mapping[str, object], source: str, index: int) -> AIProposal:
    _reject_unknown(raw, PROPOSAL_FIELDS, "proposal")
    action = str(raw.get("action") or "")
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"不允许的 action `{action}`")
    confidence = float(raw.get("confidence") or 0.0)
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence 必须位于 0..1")
    source_text = str(raw.get("source_text") or "")
    start = int(raw.get("source_start") or 0)
    end = int(raw.get("source_end") or 0)
    if start < 0 or end < start or end > len(source):
        try:
            start, end = _unique_anchor(source, source_text)
        except ValueError:
            try:
                start, end = _timeline_span_anchor(source, source_text)
                source_text = source[start:end]
            except ValueError:
                if action != "rule_candidate":
                    raise
                start, end, source_text = 0, 0, ""
    elif source_text and source[start:end] != source_text:
        try:
            start, end = _unique_anchor(source, source_text)
        except ValueError:
            try:
                start, end = _timeline_span_anchor(source, source_text)
                source_text = source[start:end]
            except ValueError:
                if action != "rule_candidate":
                    raise
                start, end, source_text = 0, 0, ""
    if end <= start and action not in {"rule_candidate", "helper_mapping"}:
        raise ValueError("候选缺少可绑定的源码范围")
    if not source_text and end > start:
        source_text = source[start:end]

    operation = dict(raw.get("operation") or {})
    helper_mapping = dict(raw.get("helper_mapping") or {})
    branch_choice = dict(raw.get("branch_choice") or {})
    memory_annotation = dict(raw.get("memory_annotation") or {})
    rule = dict(raw.get("rule") or {})
    heap_rule_call = dict(raw.get("heap_rule_call") or {})
    snapshot_effect = dict(raw.get("snapshot_effect") or {})

    if action == "heap_rule_call":
        materialized, normalized_call = HeapRuleCatalog.materialize(heap_rule_call)
        operation = materialized.to_dict()
        heap_rule_call = normalized_call
        action = str(normalized_call["placement"])

    if action in {"replace_operation", "insert_before", "insert_after", "value_fact"}:
        if not operation:
            raise ValueError("operation 不能为空")
        _validate_operation(operation)
    if action == "helper_mapping":
        _validate_helper_mapping(helper_mapping)
    if action == "branch_choice":
        _reject_unknown(branch_choice, {"branch_id", "choice"}, "branch_choice")
        if str(branch_choice.get("choice") or "") not in {"true", "false"}:
            raise ValueError("branch choice 只能是 true/false")
    if action == "memory_annotation":
        _validate_memory_annotation(memory_annotation)
    if action == "rule_candidate":
        _validate_rule(rule)
    if snapshot_effect:
        _validate_snapshot_effect(snapshot_effect)

    proposal_id = str(raw.get("proposal_id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", proposal_id):
        seed = f"{action}:{start}:{end}:{index}:{source_text}".encode("utf-8", errors="replace")
        proposal_id = "ai_" + hashlib.sha1(seed).hexdigest()[:16]
    fingerprint = str(raw.get("ast_fingerprint") or "")
    if not fingerprint and source_text:
        try:
            fingerprint = hashlib.sha1(ast.dump(ast.parse(source_text), include_attributes=False).encode("utf-8")).hexdigest()[:16]
        except SyntaxError:
            fingerprint = hashlib.sha1(source_text.encode("utf-8", errors="replace")).hexdigest()[:16]
    return AIProposal(
        proposal_id=proposal_id,
        action=action,
        source_start=start,
        source_end=end,
        source_text=source_text,
        ast_fingerprint=fingerprint,
        confidence=confidence,
        rationale=str(raw.get("rationale") or "")[:1000],
        operation=operation,
        helper_mapping=helper_mapping,
        branch_choice=branch_choice,
        memory_annotation=memory_annotation,
        rule=rule,
        heap_rule_call=heap_rule_call,
        snapshot_effect=snapshot_effect,
    )


def _validate_snapshot_effect(payload: Mapping[str, object]) -> None:
    _reject_unknown(
        payload,
        {"step", "chunk", "field", "current", "expected", "evidence", "evidence_kind", "provenance"},
        "snapshot_effect",
    )
    step = payload.get("step")
    if not isinstance(step, int) or isinstance(step, bool) or step < 0 or step > 100000:
        raise ValueError("snapshot_effect.step 必须是非负整数")
    chunk = str(payload.get("chunk") or "")
    if len(chunk) > 128:
        raise ValueError("snapshot_effect.chunk 过长")
    allowed_fields = {
        "address", "user_address", "chunk_size", "bin_location", "fd", "bk",
        "lifecycle", "aborted", "memory",
    }
    field_name = str(payload.get("field") or "")
    if field_name not in allowed_fields:
        raise ValueError(f"snapshot_effect.field `{field_name}` 不受支持")
    for name in ("current", "expected"):
        if name not in payload or len(str(payload.get(name))) > 12000:
            raise ValueError(f"snapshot_effect.{name} 缺失或过长")
    evidence = payload.get("evidence")
    if not isinstance(evidence, list) or not evidence or len(evidence) > 16:
        raise ValueError("snapshot_effect.evidence 必须包含 1..16 条证据引用")
    if any(not isinstance(item, str) or not item.strip() or len(item) > 500 for item in evidence):
        raise ValueError("snapshot_effect.evidence 包含无效引用")
    if str(payload.get("evidence_kind") or "") not in {"source", "allocator", "pwndbg"}:
        raise ValueError("snapshot_effect.evidence_kind 必须是 source/allocator/pwndbg")
    if str(payload.get("provenance") or "inferred") not in {"inferred", "assumed"}:
        raise ValueError("AI snapshot_effect 不允许声明 observed/derived provenance")


def _unique_anchor(source: str, text: str) -> tuple[int, int]:
    if not text:
        return 0, 0
    start = source.find(text)
    if start < 0 or source.find(text, start + 1) >= 0:
        raise ValueError("源码锚点无法唯一重绑")
    return start, start + len(text)


def _timeline_span_anchor(source: str, text: str) -> tuple[int, int]:
    matches = re.findall(r"\bL\d+@(\d+):(\d+)\b", text or "")
    if len(matches) != 1:
        raise ValueError("源码锚点无法唯一重绑")
    start, end = (int(matches[0][0]), int(matches[0][1]))
    if start < 0 or end <= start or end > len(source):
        raise ValueError("源码锚点无法唯一重绑")
    return start, end


def _validate_operation(payload: Mapping[str, object]) -> None:
    _reject_unknown(
        payload,
        {"op_id", "kind", "chunk", "index", "request_size", "data", "field", "value", "target", "fd_storage", "count", "note", "meta"},
        "operation",
    )
    kind = str(payload.get("kind") or "")
    if kind not in {item.value for item in HeapOperationKind}:
        raise ValueError(f"不允许的 operation kind `{kind}`")
    operation = HeapOperation.from_dict(dict(payload))
    if not 1 <= operation.count <= 256:
        raise ValueError("operation count 必须位于 1..256")
    for field_name in ("op_id", "chunk", "index", "request_size", "data", "field", "value", "target", "fd_storage", "note"):
        limit = 12000 if field_name in {"data", "value", "note"} else 512
        if len(str(getattr(operation, field_name))) > limit:
            raise ValueError(f"operation.{field_name} 过长")
    # An AI proposal may omit op_id because replacement preserves the bound
    # operation id and insertion receives a fresh local id at apply time.
    errors = validate_operation(operation if operation.op_id else HeapOperation("ai_candidate", operation.kind, **{
        key: getattr(operation, key)
        for key in ("chunk", "index", "request_size", "data", "field", "value", "target", "fd_storage", "count", "note", "meta")
    }))
    if errors:
        raise ValueError("；".join(errors))
    meta_raw = payload.get("meta") or {}
    if not isinstance(meta_raw, Mapping):
        raise ValueError("operation meta 必须是 object")
    meta = dict(meta_raw)
    _reject_unknown(meta, AI_OPERATION_META_FIELDS, "operation.meta")
    if any(not isinstance(value, (str, int, float, bool, type(None))) or len(str(value)) > 4000 for value in meta.values()):
        raise ValueError("operation meta 值类型非法或过长")
    if str(meta.get("provenance") or "").lower() == "observed":
        raise ValueError("AI operation 不能声称 observed provenance")


def _validate_helper_mapping(payload: Mapping[str, object]) -> None:
    _reject_unknown(payload, {"semantic", "function", "roles", "arity", "keywords", "parameter_names"}, "helper_mapping")
    semantic = str(payload.get("semantic") or "")
    function = str(payload.get("function") or "")
    raw_roles = payload.get("roles") or []
    if not isinstance(raw_roles, list):
        raise ValueError("helper roles 必须是数组")
    roles = list(raw_roles)
    if semantic not in ALLOWED_SEMANTICS:
        raise ValueError("helper semantic 非法")
    if not re.fullmatch(r"[A-Za-z_]\w*", function):
        raise ValueError("helper function 必须是 Python 标识符")
    if not roles or any(str(role) not in ALLOWED_ROLES for role in roles):
        raise ValueError("helper roles 非法或为空")
    try:
        arity = int(payload.get("arity") or 0)
    except (TypeError, ValueError):
        arity = -1
    if not 0 <= arity <= 32:
        raise ValueError("helper arity 非法")
    _validate_identifier_list(payload.get("keywords") or [], "helper keywords")
    parameter_names = list(payload.get("parameter_names") or [])
    _validate_identifier_list(parameter_names, "helper parameter_names")
    # Catch a frequent local-model failure before it reaches replay: mapping a
    # clearly named ``size`` parameter to index, or ``payload`` to size.  The
    # check is limited to strong CTF aliases and therefore does not guess roles
    # for opaque names such as a/b/c.
    for parameter, role in zip(parameter_names, roles):
        hinted = _parameter_role_hint(str(parameter))
        if hinted and hinted != str(role):
            raise ValueError(f"helper role 与形参 `{parameter}` 冲突: 期望 {hinted}，实际 {role}")


def _validate_memory_annotation(payload: Mapping[str, object]) -> None:
    _reject_unknown(payload, {"step", "chunk", "start", "end", "value", "state", "name", "provenance", "meaning"}, "memory_annotation")
    provenance = str(payload.get("provenance") or "inferred")
    state = str(payload.get("state") or "unknown")
    if provenance not in {"inferred", "assumed"}:
        raise ValueError("AI memory provenance 只能是 inferred/assumed")
    if state not in {"known", "unknown", "metadata"}:
        raise ValueError("AI 不能直接生成 zero/NULL 内存区域")
    start = int(payload.get("start") or 0)
    end = int(payload.get("end") or 0)
    step = int(payload.get("step") or 0)
    if start < 0 or end <= start or end - start > 0x100000:
        raise ValueError("memory annotation 范围非法")
    if not 0 <= step <= 1024:
        raise ValueError("memory annotation step 非法")
    if len(str(payload.get("chunk") or "")) > 128 or len(str(payload.get("value") or "")) > 12000:
        raise ValueError("memory annotation 字段过长")


def _validate_rule(payload: Mapping[str, object]) -> None:
    _reject_unknown(payload, {"rule_id", "semantic", "matcher", "output", "enabled", "source"}, "rule")
    semantic = str(payload.get("semantic") or "")
    matcher = dict(payload.get("matcher") or {})
    output = dict(payload.get("output") or {})
    _reject_unknown(matcher, {"function", "arity", "keywords", "parameter_names", "call_shape", "argument_equals"}, "rule.matcher")
    _reject_unknown(output, {"roles", "semantic", "arg_offset"}, "rule.output")
    if semantic not in ALLOWED_SEMANTICS:
        raise ValueError("rule semantic 非法")
    function = str(matcher.get("function") or "")
    if not re.fullmatch(r"[A-Za-z_]\w*", function):
        raise ValueError("rule matcher.function 非法")
    arity = int(matcher.get("arity") or 0)
    if not 0 <= arity <= 32:
        raise ValueError("rule matcher.arity 非法")
    _validate_identifier_list(matcher.get("keywords") or [], "rule matcher.keywords")
    _validate_identifier_list(matcher.get("parameter_names") or [], "rule matcher.parameter_names")
    argument_equals = matcher.get("argument_equals") or {}
    if not isinstance(argument_equals, Mapping) or len(argument_equals) > 8:
        raise ValueError("rule matcher.argument_equals 必须是最多 8 项的 object")
    for position, expected in argument_equals.items():
        if not str(position).isdigit() or not 0 <= int(position) <= 31:
            raise ValueError("rule matcher.argument_equals 位置非法")
        if not isinstance(expected, (str, int, float, bool)) or len(str(expected)) > 120:
            raise ValueError("rule matcher.argument_equals 值非法")
    raw_roles = output.get("roles") or []
    if not isinstance(raw_roles, list):
        raise ValueError("rule output.roles 必须是数组")
    roles = list(raw_roles)
    if not roles or any(str(role) not in ALLOWED_ROLES for role in roles):
        raise ValueError("rule output.roles 非法")
    try:
        arg_offset = int(output.get("arg_offset") or 0)
    except (TypeError, ValueError):
        arg_offset = -1
    if not 0 <= arg_offset <= 31:
        raise ValueError("rule output.arg_offset 非法")
    if argument_equals and arg_offset <= max(int(position) for position in argument_equals):
        raise ValueError("dispatcher rule 必须用 output.arg_offset 跳过已匹配的选择器参数")
    call_shape = matcher.get("call_shape")
    if call_shape is not None and not isinstance(call_shape, Mapping):
        raise ValueError("rule matcher.call_shape 必须是 object")
    if isinstance(call_shape, Mapping):
        _validate_call_shape(call_shape)


def _validate_call_shape(payload: Mapping[str, object]) -> None:
    _reject_unknown(payload, {"callee", "positional", "keywords"}, "rule.matcher.call_shape")
    if str(payload.get("callee") or "") not in {"name", "method"}:
        raise ValueError("call_shape.callee 非法")
    positional = payload.get("positional") or []
    keywords = payload.get("keywords") or []
    if not isinstance(positional, list) or len(positional) > 32 or any(not isinstance(item, str) or len(item) > 80 for item in positional):
        raise ValueError("call_shape.positional 非法")
    if not isinstance(keywords, list) or len(keywords) > 32:
        raise ValueError("call_shape.keywords 非法")
    for item in keywords:
        if not isinstance(item, Mapping):
            raise ValueError("call_shape keyword 必须是 object")
        _reject_unknown(item, {"name", "shape"}, "call_shape.keyword")
        if len(str(item.get("name") or "")) > 80 or len(str(item.get("shape") or "")) > 80:
            raise ValueError("call_shape keyword 过长")


def _reject_unknown(payload: Mapping[str, object], allowed: set[str], label: str) -> None:
    unknown = sorted(str(key) for key in payload if str(key) not in allowed)
    if unknown:
        raise ValueError(f"{label} 包含未知字段: {', '.join(unknown)}")


def _validate_identifier_list(value: object, label: str) -> None:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError(f"{label} 必须是最多 32 项的数组")
    if any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z_]\w*", item) for item in value):
        raise ValueError(f"{label} 包含非法标识符")


def _parameter_role_hint(name: str) -> str:
    key = name.lower().strip("_")
    if key in {"idx", "index", "id", "sid", "uid", "slot", "pos", "chunk_idx", "note_idx"}:
        return "index"
    if key in {"size", "sz", "request_size", "chunk_size", "content_size", "name_size"}:
        return "size"
    if key in {"data", "content", "payload", "buf", "buffer", "body", "name", "text", "value"}:
        return "data"
    if key in {"src", "source", "src_idx", "from_idx"}:
        return "src"
    if key in {"dst", "dest", "destination", "dst_idx", "to_idx"}:
        return "dst"
    if key in {"len", "length", "count", "cnt"}:
        return "length"
    return ""
