"""Reviewed runtime-semantics layer for embedded typed programs.

This module is deliberately downstream of ``embedded_execution``.  A static type
confusion relation still does not tell us how the resident bytes are interpreted
by the target runtime, nor what a target builtin such as an indexed update does.
Callers must therefore provide an explicit reviewed runtime policy before object
layout or memory-write facts are derived.

The implementation is generic and evidence-preserving:

* exact constant string returns can be decoded into bytes;
* reviewed object layouts interpret those bytes field-by-field;
* reviewed indexed-add builtins can turn a reachable call into a constrained
  additive write only when the object, index, delta and bounds are all known;
* simple early-return guards are evaluated only from statically known integer
  parameter values. Unknown control flow stays unknown.

No challenge names, addresses, GOT symbols or exploit targets are embedded here.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import re
from typing import Any

from pwncraft.features.audit.embedded_program import EmbeddedFunction, EmbeddedProgram, EmbeddedStatement


_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_FUNCTION_START_RE = re.compile(rf"^\s*function\s+(?P<name>{_IDENT})\s*\(")
_RETURN_RE = re.compile(r"^\s*return\s+(?P<expr>.+?)\s*;\s*$")
_EARLY_RETURN_RE = re.compile(
    r"if\s*\((?P<condition>[^\n{}]+)\)\s*\{\s*return\s*;\s*\}\s*;?",
    re.MULTILINE,
)


@dataclass(frozen=True)
class EmbeddedFieldLayout:
    name: str
    offset: int
    width: int
    kind: str = "int"
    signed: bool = False

    def validate(self, object_size: int) -> None:
        if not self.name.strip():
            raise ValueError("runtime field name must be non-empty")
        if self.kind not in {"int", "pointer"}:
            raise ValueError(f"unsupported runtime field kind: {self.kind}")
        if self.offset < 0 or self.width <= 0 or self.offset + self.width > object_size:
            raise ValueError(f"runtime field {self.name} is outside object layout")


@dataclass(frozen=True)
class EmbeddedObjectLayout:
    type_name: str
    size: int
    fields: tuple[EmbeddedFieldLayout, ...]

    def validate(self) -> None:
        if not self.type_name.strip():
            raise ValueError("runtime object type must be non-empty")
        if self.size <= 0:
            raise ValueError("runtime object size must be positive")
        seen: set[str] = set()
        for field in self.fields:
            field.validate(self.size)
            if field.name in seen:
                raise ValueError(f"duplicate runtime field: {field.name}")
            seen.add(field.name)


@dataclass(frozen=True)
class EmbeddedIndexedAddSemantics:
    callee: str
    object_type: str
    object_arg_index: int
    index_arg_index: int
    delta_arg_index: int
    data_field: str
    size_field: str
    element_width: int = 8
    bounds_kind: str = "nonnegative_lt_size"

    def validate(self) -> None:
        if not self.callee.strip() or not self.object_type.strip():
            raise ValueError("indexed-add callee/object type must be non-empty")
        if min(self.object_arg_index, self.index_arg_index, self.delta_arg_index) < 0:
            raise ValueError("indexed-add argument indexes must be non-negative")
        if self.element_width <= 0:
            raise ValueError("indexed-add element width must be positive")
        if self.bounds_kind != "nonnegative_lt_size":
            raise ValueError(f"unsupported indexed-add bounds: {self.bounds_kind}")


@dataclass(frozen=True)
class EmbeddedRuntimePolicy:
    name: str
    object_layouts: tuple[EmbeddedObjectLayout, ...]
    indexed_add_operations: tuple[EmbeddedIndexedAddSemantics, ...] = ()
    endianness: str = "little"
    pointer_width: int = 8
    provenance: str = "REVIEWED_RUNTIME_POLICY"

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("runtime policy name must be non-empty")
        if self.endianness not in {"little", "big"}:
            raise ValueError(f"unsupported runtime endianness: {self.endianness}")
        if self.pointer_width <= 0:
            raise ValueError("runtime pointer width must be positive")
        for layout in self.object_layouts:
            layout.validate()
        for operation in self.indexed_add_operations:
            operation.validate()
            layout = next((item for item in self.object_layouts if item.type_name == operation.object_type), None)
            if layout is None:
                raise ValueError(f"missing object layout for indexed-add type: {operation.object_type}")
            names = {field.name for field in layout.fields}
            if operation.data_field not in names or operation.size_field not in names:
                raise ValueError("indexed-add data/size fields must exist in the object layout")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _FunctionSource:
    name: str
    start_line: int
    end_line: int
    lines: tuple[str, ...]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _decode_source(content: str | bytes) -> str | None:
    if isinstance(content, str):
        return content
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _extract_function_sources(content: str | bytes) -> dict[str, _FunctionSource]:
    text = _decode_source(content)
    if text is None:
        return {}
    lines = text.splitlines()
    result: dict[str, _FunctionSource] = {}
    current_name = ""
    current_start = 0
    current_lines: list[str] = []
    brace_depth = 0

    for line_no, raw_line in enumerate(lines, start=1):
        if not current_name:
            match = _FUNCTION_START_RE.match(raw_line)
            if match is None:
                continue
            current_name = match.group("name")
            current_start = line_no
            current_lines = [raw_line]
            brace_depth = raw_line.count("{") - raw_line.count("}")
            if brace_depth <= 0:
                result[current_name] = _FunctionSource(
                    current_name, current_start, line_no, tuple(current_lines)
                )
                current_name = ""
            continue

        current_lines.append(raw_line)
        brace_depth += raw_line.count("{") - raw_line.count("}")
        if brace_depth <= 0:
            result[current_name] = _FunctionSource(
                current_name, current_start, line_no, tuple(current_lines)
            )
            current_name = ""
            current_start = 0
            current_lines = []
            brace_depth = 0
    return result


def _constant_return_bytes(source: _FunctionSource) -> bytes | None:
    expressions: list[str] = []
    for raw_line in source.lines:
        match = _RETURN_RE.match(raw_line)
        if match is not None:
            expressions.append(match.group("expr").strip())
    if len(expressions) != 1:
        return None
    try:
        value = ast.literal_eval(expressions[0])
    except (SyntaxError, ValueError):
        return None
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return None
    try:
        return value.encode("latin-1")
    except UnicodeEncodeError:
        return None


def _eval_int_node(node: ast.AST, env: dict[str, int]) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return int(node.value)
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.UnaryOp):
        value = _eval_int_node(node.operand, env)
        if value is None:
            return None
        if isinstance(node.op, ast.UAdd):
            return value
        if isinstance(node.op, ast.USub):
            return -value
        return None
    if isinstance(node, ast.BinOp):
        left = _eval_int_node(node.left, env)
        right = _eval_int_node(node.right, env)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.FloorDiv) and right != 0:
            return left // right
        if isinstance(node.op, ast.Mod) and right != 0:
            return left % right
    return None


def _eval_int_expr(expression: str, env: dict[str, int]) -> int | None:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return None
    return _eval_int_node(tree.body, env)


def _eval_condition(expression: str, env: dict[str, int]) -> bool | None:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return None
    node = tree.body
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = _eval_int_node(node.left, env)
    right = _eval_int_node(node.comparators[0], env)
    if left is None or right is None:
        return None
    op = node.ops[0]
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    return None


def _field_values(
    raw: bytes,
    layout: EmbeddedObjectLayout,
    policy: EmbeddedRuntimePolicy,
) -> list[dict[str, Any]] | None:
    if len(raw) != layout.size:
        return None
    values: list[dict[str, Any]] = []
    for field in layout.fields:
        chunk = raw[field.offset:field.offset + field.width]
        value = int.from_bytes(chunk, policy.endianness, signed=field.signed)
        values.append({
            "name": field.name,
            "kind": field.kind,
            "offset": field.offset,
            "width": field.width,
            "signed": field.signed,
            "raw_hex": chunk.hex(),
            "value": value,
        })
    return values


def _function_by_name(program: EmbeddedProgram, name: str) -> EmbeddedFunction | None:
    return next((function for function in program.functions if function.name == name), None)


def _statement_by_order(function: EmbeddedFunction, order: int) -> EmbeddedStatement | None:
    return next((statement for statement in function.statements if statement.order == order), None)


def _loop_entry_integer_state(
    execution_function: dict[str, Any],
    call_line: int,
) -> dict[str, int] | None:
    candidates = [
        loop for loop in execution_function.get("loops", [])
        if loop.get("proves_second_iteration")
        and int(loop.get("start_line", 0)) < call_line < int(loop.get("end_line", 0))
    ]
    if len(candidates) != 1:
        return None
    state = candidates[0].get("integer_state_after_first_iteration") or {}
    if not all(isinstance(key, str) and isinstance(value, int) for key, value in state.items()):
        return None
    return dict(state)


def _bind_known_integer_parameters(
    caller: EmbeddedFunction,
    callee: EmbeddedFunction,
    call: EmbeddedStatement,
    execution_function: dict[str, Any],
) -> dict[str, int]:
    state = _loop_entry_integer_state(execution_function, call.line)
    if state is None:
        return {}
    result: dict[str, int] = {}
    for index, parameter in enumerate(callee.parameters):
        if parameter.type_name != "int" or index >= len(call.arguments):
            continue
        value = _eval_int_expr(call.arguments[index], state)
        if value is not None:
            result[parameter.name] = value
    return result


def _simple_call_reachable(
    source: _FunctionSource | None,
    call: EmbeddedStatement,
    env: dict[str, int],
) -> bool | None:
    if source is None:
        return None
    relative_end = call.line - source.start_line
    if relative_end < 0:
        return None
    prefix = "\n".join(source.lines[:relative_end + 1])
    for match in _EARLY_RETURN_RE.finditer(prefix):
        result = _eval_condition(match.group("condition").strip(), env)
        if result is None:
            return None
        if result is True:
            return False
    return True


def _producer_bytes_for_confusion(
    program: EmbeddedProgram,
    function_sources: dict[str, _FunctionSource],
    execution_function: dict[str, Any],
    confusion: dict[str, Any],
) -> tuple[bytes, str, int] | None:
    caller = _function_by_name(program, str(confusion.get("function") or ""))
    if caller is None:
        return None
    producer_variable = str(confusion.get("resident_variable") or "")
    slot = confusion.get("slot")
    flows = [
        item for item in execution_function.get("cross_iteration_value_flows", [])
        if item.get("producer_variable") == producer_variable
        and item.get("slot") == slot
    ]
    if len(flows) != 1:
        return None
    producer_order = int(flows[0].get("producer_order_iteration_1", 0))
    statement = _statement_by_order(caller, producer_order)
    if statement is None or statement.kind != "assignment" or statement.target != producer_variable:
        return None
    if not statement.callee:
        return None
    producer_source = function_sources.get(statement.callee)
    if producer_source is None:
        return None
    raw = _constant_return_bytes(producer_source)
    if raw is None:
        return None
    return raw, statement.callee, statement.line


def _confused_parameter_name(
    caller: EmbeddedFunction,
    callee: EmbeddedFunction,
    confusion: dict[str, Any],
) -> tuple[EmbeddedStatement, str] | None:
    call = _statement_by_order(caller, int(confusion.get("call_order", 0)))
    if call is None or call.kind != "call" or call.callee != callee.name:
        return None
    source_variable = str(confusion.get("consumed_through_variable") or "")
    matches = [
        index for index, argument in enumerate(call.arguments)
        if argument.strip() == source_variable
    ]
    if len(matches) != 1 or matches[0] >= len(callee.parameters):
        return None
    return call, callee.parameters[matches[0]].name


def _derive_indexed_add_writes(
    program: EmbeddedProgram,
    function_sources: dict[str, _FunctionSource],
    execution_function: dict[str, Any],
    confusion: dict[str, Any],
    field_values: list[dict[str, Any]],
    policy: EmbeddedRuntimePolicy,
) -> list[dict[str, Any]]:
    caller = _function_by_name(program, str(confusion.get("function") or ""))
    callee = _function_by_name(program, str(confusion.get("callee") or ""))
    if caller is None or callee is None:
        return []
    binding = _confused_parameter_name(caller, callee, confusion)
    if binding is None:
        return []
    caller_call, confused_parameter = binding
    int_env = _bind_known_integer_parameters(caller, callee, caller_call, execution_function)
    by_name = {item["name"]: item["value"] for item in field_values}

    writes: list[dict[str, Any]] = []
    for operation in policy.indexed_add_operations:
        if operation.object_type != confusion.get("consumed_as_type"):
            continue
        for call in callee.statements:
            if call.kind != "call" or call.callee != operation.callee or call.loop_depth != 0:
                continue
            required_index = max(
                operation.object_arg_index,
                operation.index_arg_index,
                operation.delta_arg_index,
            )
            if len(call.arguments) <= required_index:
                continue
            if call.arguments[operation.object_arg_index].strip() != confused_parameter:
                continue
            reachable = _simple_call_reachable(function_sources.get(callee.name), call, int_env)
            if reachable is not True:
                continue
            index = _eval_int_expr(call.arguments[operation.index_arg_index], int_env)
            delta = _eval_int_expr(call.arguments[operation.delta_arg_index], int_env)
            data = by_name.get(operation.data_field)
            size = by_name.get(operation.size_field)
            if None in {index, delta, data, size}:
                continue
            assert isinstance(index, int) and isinstance(delta, int)
            assert isinstance(data, int) and isinstance(size, int)
            if operation.bounds_kind == "nonnegative_lt_size" and not (0 <= index < size):
                continue
            address = data + index * operation.element_width
            pointer_limit = 1 << (policy.pointer_width * 8)
            if not (0 <= address < pointer_limit):
                continue
            writes.append({
                "kind": "indexed_additive_write",
                "callee": call.callee,
                "function": callee.name,
                "line": call.line,
                "object_type": operation.object_type,
                "object_parameter": confused_parameter,
                "data": data,
                "size": size,
                "index": index,
                "delta": delta,
                "element_width": operation.element_width,
                "address": address,
                "width": operation.element_width,
                "bounds_proven": True,
                "operation": "add",
                "state": "derived_static",
                "runtime_observed": False,
                "provenance": "TYPE_CONFUSION_PLUS_REVIEWED_RUNTIME_POLICY_PLUS_STATIC_ARGUMENT_EVAL",
            })
    return writes


def analyze_embedded_runtime_semantics(
    program: EmbeddedProgram,
    execution_semantics: dict[str, Any],
    content: str | bytes,
    policy: EmbeddedRuntimePolicy,
) -> dict[str, Any]:
    """Interpret confused values and derive constrained runtime writes.

    This function does not execute the embedded program.  It requires a reviewed
    target-runtime policy, an already-proven static type confusion relation, an
    exact constant producer value and a statically reachable reviewed builtin.
    """
    policy.validate()
    layouts = {layout.type_name: layout for layout in policy.object_layouts}
    function_sources = _extract_function_sources(content)
    results: list[dict[str, Any]] = []
    primitives: list[dict[str, Any]] = []

    for execution_function in execution_semantics.get("functions", []):
        for confusion in execution_function.get("runtime_type_confusions", []):
            if confusion.get("state") != "derived_static":
                continue
            layout = layouts.get(str(confusion.get("consumed_as_type") or ""))
            if layout is None:
                continue
            producer = _producer_bytes_for_confusion(
                program, function_sources, execution_function, confusion
            )
            if producer is None:
                continue
            raw, producer_function, producer_line = producer
            fields = _field_values(raw, layout, policy)
            if fields is None:
                continue
            interpretation = {
                "kind": "forged_object_field_interpretation",
                "function": confusion.get("function"),
                "slot": confusion.get("slot"),
                "resident_variable": confusion.get("resident_variable"),
                "resident_type": confusion.get("resident_type"),
                "consumed_as_type": confusion.get("consumed_as_type"),
                "producer_function": producer_function,
                "producer_line": producer_line,
                "raw_length": len(raw),
                "raw_hex": raw.hex(),
                "object_size": layout.size,
                "endianness": policy.endianness,
                "fields": fields,
                "state": "derived_static",
                "runtime_observed": False,
                "provenance": "TYPE_CONFUSION_PLUS_EXACT_RETURN_BYTES_PLUS_REVIEWED_RUNTIME_POLICY",
            }
            writes = _derive_indexed_add_writes(
                program,
                function_sources,
                execution_function,
                confusion,
                fields,
                policy,
            )
            results.append({
                "type_confusion": confusion,
                "field_interpretation": interpretation,
                "indexed_additive_writes": writes,
            })
            for write in writes:
                primitives.append({
                    "name": "constrained additive 64-bit write" if write["width"] == 8 else "constrained additive write",
                    "domain": "memory_write",
                    "state": "derived_static",
                    "source": "embedded-runtime-policy",
                    "confidence": 1.0,
                    "address": write["address"],
                    "width": write["width"],
                    "delta": write["delta"],
                    "evidence": [interpretation, write],
                    "limitations": [
                        "the write is statically derived, not runtime-observed",
                        "the primitive is additive and bounds-constrained; it is not labeled arbitrary write",
                        "target-symbol identity and control-flow takeover are outside this layer",
                    ],
                })

    return {
        "policy": policy.to_dict(),
        "relations": results,
        "primitives": primitives,
        "provenance": "EMBEDDED_EXECUTION_PLUS_REVIEWED_RUNTIME_POLICY",
        "limitations": [
            "runtime object layout and builtin effects are policy-gated reviewed facts",
            "only exact constant return bytes and a small deterministic integer/control subset are handled",
            "GOT/symbol identification and exploit planning are intentionally deferred",
        ],
    }
