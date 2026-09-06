from __future__ import annotations

import re

from pwnbao.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwnbao.features.heapviz.scenario import HeapScenario


IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def validate_operation(operation: HeapOperation) -> list[str]:
    errors: list[str] = []
    if not operation.op_id:
        errors.append("operation 缺少 op_id")
    if operation.chunk and not IDENT_RE.fullmatch(operation.chunk):
        errors.append(f"{operation.op_id}: chunk 名只能使用英文、数字和下划线")
    if operation.kind == HeapOperationKind.ALLOC and not operation.request_size:
        errors.append(f"{operation.op_id}: alloc 需要申请大小")
    needs_chunk_or_index = {
        HeapOperationKind.FREE,
        HeapOperationKind.EDIT,
        HeapOperationKind.SHOW,
        HeapOperationKind.SAFE_LINK_FD,
        HeapOperationKind.OVERFLOW_HEADER,
        HeapOperationKind.POISON_FD,
        HeapOperationKind.UNLINK_PREPARE,
        HeapOperationKind.LEAK_MAIN_ARENA,
    }
    if operation.kind in needs_chunk_or_index:
        if not operation.chunk and not operation.index:
            errors.append(f"{operation.op_id}: 需要 chunk 名或菜单索引")
    if operation.kind in {HeapOperationKind.SAFE_LINK_FD, HeapOperationKind.POISON_FD, HeapOperationKind.MALLOC_TO_TARGET} and not operation.target:
        errors.append(f"{operation.op_id}: 需要目标地址")
    if operation.kind == HeapOperationKind.FAKE_CHUNK and not (operation.chunk or operation.target):
        errors.append(f"{operation.op_id}: fake chunk 需要名称或目标地址")
    return errors


def validate_scenario(scenario: HeapScenario) -> list[str]:
    errors: list[str] = []
    if scenario.schema_version < 1 or scenario.schema_version > 3:
        errors.append(f"不支持的场景 schema_version: {scenario.schema_version}")
    seen: set[str] = set()
    for operation in scenario.operations:
        if operation.op_id in seen:
            errors.append(f"重复 operation id: {operation.op_id}")
        seen.add(operation.op_id)
        errors.extend(validate_operation(operation))
    for branch_id, choice in scenario.branch_choices.items():
        if not branch_id or choice not in {"true", "false"}:
            errors.append(f"非法分支选择: {branch_id}={choice}")
    allowed_roles = {"index", "size", "data", "src", "dst", "length"}
    for index, rule in enumerate(scenario.ai_scene_rules, 1):
        semantic = str(rule.get("semantic") or "")
        matcher = dict(rule.get("matcher") or {})
        output = dict(rule.get("output") or {})
        function = str(matcher.get("function") or "")
        roles = [str(item) for item in list(output.get("roles") or [])]
        if semantic not in {"alloc", "free", "edit", "show", "copy"}:
            errors.append(f"AI scene rule {index}: semantic 非法")
        if not IDENT_RE.fullmatch(function):
            errors.append(f"AI scene rule {index}: function 非法")
        if not roles or any(role not in allowed_roles for role in roles):
            errors.append(f"AI scene rule {index}: roles 非法")
        try:
            arity = int(matcher.get("arity") or 0)
        except (TypeError, ValueError):
            arity = -1
        if not 0 <= arity <= 32:
            errors.append(f"AI scene rule {index}: arity 非法")
    for index, annotation in enumerate(scenario.ai_memory_annotations, 1):
        provenance = str(annotation.get("provenance") or "inferred")
        state = str(annotation.get("state") or "unknown")
        try:
            start = int(annotation.get("start") or 0)
            end = int(annotation.get("end") or 0)
            step = int(annotation.get("step") or 0)
        except (TypeError, ValueError):
            start, end, step = 0, 0, -1
        if provenance not in {"inferred", "assumed"}:
            errors.append(f"AI memory annotation {index}: provenance 非法")
        if state not in {"known", "unknown", "metadata"}:
            errors.append(f"AI memory annotation {index}: state 非法")
        if start < 0 or end <= start or end - start > 0x100000 or step < 0:
            errors.append(f"AI memory annotation {index}: range/step 非法")
    return errors
