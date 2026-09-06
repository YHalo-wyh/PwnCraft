"""Deterministic cross-iteration value-flow facts for reviewed embedded compilers.

This layer sits strictly after ``embedded_compiler``.  It consumes already-
reviewed slot assignments/reuse plus concrete embedded source structure and asks
one narrow question: can a value written into a reused compiler slot survive the
end of one ``do/while`` iteration and be consumed through the old source-level
variable on the next iteration?

The analysis never executes the wrapper or embedded program.  It only evaluates
a tiny integer-expression subset needed to prove whether a ``do/while`` condition
is true after the first iteration.  Unknown syntax stays unknown.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import re
from typing import Any

from pwncraft.features.audit.embedded_program import (
    EmbeddedFunction,
    EmbeddedProgram,
    EmbeddedStatement,
)


_DO_RE = re.compile(r"^\s*do\s*\{\s*$")
_DO_WHILE_RE = re.compile(r"^\s*}\s*while\s*\((?P<condition>.*)\)\s*;\s*$")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class _LoopRange:
    start_line: int
    end_line: int
    condition: str


def _decode_source(content: str | bytes) -> str | None:
    if isinstance(content, str):
        return content
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _extract_do_while_ranges(content: str | bytes) -> list[_LoopRange]:
    text = _decode_source(content)
    if text is None:
        return []
    stack: list[int] = []
    loops: list[_LoopRange] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if _DO_RE.match(raw_line):
            stack.append(line_no)
            continue
        match = _DO_WHILE_RE.match(raw_line)
        if match is not None and stack:
            loops.append(_LoopRange(
                start_line=stack.pop(),
                end_line=line_no,
                condition=match.group("condition").strip(),
            ))
    loops.sort(key=lambda item: (item.start_line, item.end_line))
    return loops


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
    if isinstance(op, ast.Lt):
        return left < right
    if isinstance(op, ast.LtE):
        return left <= right
    if isinstance(op, ast.Gt):
        return left > right
    if isinstance(op, ast.GtE):
        return left >= right
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    return None


def _typed_locals(function: EmbeddedFunction) -> dict[str, str]:
    return {item.name: item.type_name for item in function.locals}


def _loop_statements(function: EmbeddedFunction, loop: _LoopRange) -> list[EmbeddedStatement]:
    return [
        statement
        for statement in function.statements
        if loop.start_line < statement.line < loop.end_line
    ]


def _apply_int_assignment(
    statement: EmbeddedStatement,
    env: dict[str, int],
    local_types: dict[str, str],
) -> None:
    if statement.kind != "assignment" or local_types.get(statement.target) != "int":
        return
    value = _eval_int_expr(statement.expression, env)
    if value is None:
        env.pop(statement.target, None)
    else:
        env[statement.target] = value


def _analyze_loop_state(function: EmbeddedFunction, loop: _LoopRange) -> dict[str, Any] | None:
    body = _loop_statements(function, loop)
    depths = [statement.loop_depth for statement in body if statement.loop_depth > 0]
    if not depths:
        return None
    loop_depth = min(depths)
    local_types = _typed_locals(function)
    env: dict[str, int] = {}

    for statement in function.statements:
        if statement.line >= loop.start_line:
            break
        if statement.loop_depth < loop_depth:
            _apply_int_assignment(statement, env, local_types)

    before = dict(env)
    for statement in body:
        if statement.loop_depth == loop_depth:
            _apply_int_assignment(statement, env, local_types)
    condition_value = _eval_condition(loop.condition, env)

    return {
        "kind": "do_while_iteration_state",
        "function": function.name,
        "start_line": loop.start_line,
        "end_line": loop.end_line,
        "loop_depth": loop_depth,
        "condition": loop.condition,
        "integer_state_before_first_iteration": before,
        "integer_state_after_first_iteration": dict(env),
        "condition_after_first_iteration": condition_value,
        "proves_second_iteration": condition_value is True,
        "provenance": "EMBEDDED_STRUCTURE_STATIC_INTEGER_EVAL",
    }


def _argument_mentions(statement: EmbeddedStatement, variable: str) -> bool:
    if statement.kind != "call":
        return False
    for argument in statement.arguments:
        if variable in _IDENT_RE.findall(argument):
            return True
    return False


def _same_slot_assignment_orders(
    statements: list[EmbeddedStatement],
    slot_by_variable: dict[str, int],
    slot: int,
    loop_depth: int,
) -> list[int]:
    return [
        statement.order
        for statement in statements
        if statement.kind == "assignment"
        and statement.loop_depth == loop_depth
        and slot_by_variable.get(statement.target) == slot
    ]


def _derive_cross_iteration_relations(
    function: EmbeddedFunction,
    compiler_fact: dict[str, Any],
    loop: _LoopRange,
    loop_state: dict[str, Any],
    *,
    codegen_preserves_call_arguments: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not loop_state.get("proves_second_iteration") or not codegen_preserves_call_arguments:
        return [], []

    body = _loop_statements(function, loop)
    slot_by_variable = {
        item["variable"]: int(item["slot"])
        for item in compiler_fact.get("slot_assignments", [])
    }
    omission_by_order = {
        int(item["order"]): item
        for item in compiler_fact.get("liveness_omissions", [])
        if item.get("codegen_preserves_arguments")
    }

    value_flows: list[dict[str, Any]] = []
    type_confusions: list[dict[str, Any]] = []
    seen: set[tuple[int, int, str, str]] = set()

    for reuse in compiler_fact.get("slot_reuse_relations", []):
        if not reuse.get("cross_type"):
            continue
        from_variable = str(reuse["from_variable"])
        to_variable = str(reuse["to_variable"])
        slot = int(reuse["slot"])

        for call in body:
            if call.loop_depth <= 0 or not _argument_mentions(call, from_variable):
                continue
            omission = omission_by_order.get(call.order)
            if omission is None or from_variable not in omission.get("variables", []):
                continue

            later_writes = [
                statement
                for statement in body
                if statement.kind == "assignment"
                and statement.loop_depth == call.loop_depth
                and statement.target == to_variable
                and statement.order > call.order
            ]
            if not later_writes:
                continue
            write = later_writes[0]

            same_slot_orders = _same_slot_assignment_orders(
                body, slot_by_variable, slot, call.loop_depth
            )
            if any(order < call.order for order in same_slot_orders):
                # The next iteration refreshes the physical slot before the old
                # variable is consumed, so the previous resident value cannot be
                # proven to survive into this call.
                continue
            if any(order > write.order for order in same_slot_orders):
                # Something else overwrites the slot before loop back-edge.
                continue

            key = (loop.start_line, call.order, from_variable, to_variable)
            if key in seen:
                continue
            seen.add(key)
            flow = {
                "kind": "cross_iteration_slot_value_flow",
                "function": function.name,
                "loop_start_line": loop.start_line,
                "loop_end_line": loop.end_line,
                "slot": slot,
                "producer_variable": to_variable,
                "producer_type": reuse["to_type"],
                "producer_order_iteration_1": write.order,
                "consumer_variable": from_variable,
                "consumer_type": reuse["from_type"],
                "consumer_callee": call.callee,
                "consumer_order_iteration_2": call.order,
                "source_argument": next(
                    argument
                    for argument in call.arguments
                    if from_variable in _IDENT_RE.findall(argument)
                ),
                "resident_value_survives_loop_backedge": True,
                "second_iteration_proven": True,
                "provenance": "REVIEWED_SLOT_REUSE_PLUS_STATIC_LOOP_STATE",
            }
            value_flows.append(flow)
            type_confusions.append({
                "kind": "runtime_type_confusion",
                "function": function.name,
                "slot": slot,
                "iteration": 2,
                "resident_variable": to_variable,
                "resident_type": reuse["to_type"],
                "consumed_through_variable": from_variable,
                "consumed_as_type": reuse["from_type"],
                "callee": call.callee,
                "call_order": call.order,
                "state": "derived_static",
                "runtime_observed": False,
                "provenance": "EMBEDDED_STRUCTURE_PLUS_REVIEWED_COMPILER_POLICY_PLUS_STATIC_LOOP_STATE",
            })

    return value_flows, type_confusions


def analyze_embedded_execution_semantics(
    program: EmbeddedProgram,
    compiler_semantics: dict[str, Any],
    content: str | bytes,
) -> dict[str, Any]:
    """Derive auditable cross-iteration slot value flow without executing code.

    The current proof is intentionally narrow: a simple ``do/while`` condition
    must be evaluable after the first iteration, reviewed compiler facts must
    prove cross-type slot reuse, and code generation must preserve the omitted
    call argument.  Anything else remains unknown.
    """
    loops = _extract_do_while_ranges(content)
    compiler_functions = {
        item["function"]: item
        for item in compiler_semantics.get("functions", [])
    }
    policy = compiler_semantics.get("policy") or {}
    codegen_preserves = bool(policy.get("codegen_preserves_call_arguments"))

    functions: list[dict[str, Any]] = []
    for function in program.functions:
        compiler_fact = compiler_functions.get(function.name)
        if compiler_fact is None:
            continue
        function_loops: list[dict[str, Any]] = []
        value_flows: list[dict[str, Any]] = []
        type_confusions: list[dict[str, Any]] = []
        for loop in loops:
            body = _loop_statements(function, loop)
            if not body:
                continue
            loop_state = _analyze_loop_state(function, loop)
            if loop_state is None:
                continue
            function_loops.append(loop_state)
            flows, confusions = _derive_cross_iteration_relations(
                function,
                compiler_fact,
                loop,
                loop_state,
                codegen_preserves_call_arguments=codegen_preserves,
            )
            value_flows.extend(flows)
            type_confusions.extend(confusions)
        if function_loops or value_flows or type_confusions:
            functions.append({
                "function": function.name,
                "loops": function_loops,
                "cross_iteration_value_flows": value_flows,
                "runtime_type_confusions": type_confusions,
            })

    return {
        "functions": functions,
        "provenance": "EMBEDDED_STRUCTURE_PLUS_REVIEWED_COMPILER_POLICY_PLUS_STATIC_LOOP_STATE",
        "limitations": [
            "the relation is statically derived and is not a GDB/runtime observation",
            "only a small deterministic integer-expression subset is evaluated",
            "type confusion does not by itself prove memory corruption or an arbitrary-write primitive",
        ],
    }
