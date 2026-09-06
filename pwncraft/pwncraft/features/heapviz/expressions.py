from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ExpressionResult:
    """Safe evaluation result used by HeapViz.

    HeapViz deliberately supports only integer arithmetic.  Unknown names are
    preserved symbolically instead of being executed or guessed.
    """

    source: str
    value: int | None

    @property
    def resolved(self) -> bool:
        return self.value is not None

    def display(self, default: str = "未知") -> str:
        if self.value is not None:
            return hex(self.value)
        return self.source or default


_ALLOWED_BINOPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.FloorDiv: lambda a, b: a // b if b else None,
    ast.Mod: lambda a, b: a % b if b else None,
    ast.LShift: lambda a, b: a << b,
    ast.RShift: lambda a, b: a >> b,
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.BitXor: lambda a, b: a ^ b,
}

_ALLOWED_UNARY = {
    ast.UAdd: lambda value: value,
    ast.USub: lambda value: -value,
    ast.Invert: lambda value: ~value,
}


def evaluate_int_expr(
    value: str | int | None,
    variables: Mapping[str, str | int] | None = None,
    *,
    _seen: frozenset[str] = frozenset(),
) -> ExpressionResult:
    if value is None:
        return ExpressionResult("", None)
    if isinstance(value, int):
        return ExpressionResult(str(value), value)
    source = str(value).strip()
    if not source:
        return ExpressionResult("", None)
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError:
        return ExpressionResult(source, None)

    env = variables or {}

    def eval_node(node: ast.AST) -> int | None:
        if isinstance(node, ast.Expression):
            return eval_node(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
        if isinstance(node, ast.Name):
            if node.id in _seen or node.id not in env:
                return None
            nested = evaluate_int_expr(env[node.id], env, _seen=_seen | {node.id})
            return nested.value
        if isinstance(node, ast.UnaryOp):
            operand = eval_node(node.operand)
            function = _ALLOWED_UNARY.get(type(node.op))
            if operand is None or function is None:
                return None
            return function(operand)
        if isinstance(node, ast.BinOp):
            left = eval_node(node.left)
            right = eval_node(node.right)
            function = _ALLOWED_BINOPS.get(type(node.op))
            if left is None or right is None or function is None:
                return None
            try:
                return function(left, right)
            except (ArithmeticError, ValueError, OverflowError):
                return None
        # Explicitly reject calls, attributes, subscripts, comprehensions, etc.
        return None

    return ExpressionResult(source, eval_node(tree))


def parse_int_expr(value: str | int | None, variables: Mapping[str, str | int] | None = None) -> int | None:
    return evaluate_int_expr(value, variables).value


def collect_integer_assignments(source: str) -> dict[str, str]:
    """Collect simple integer/symbolic assignments from Python EXP text.

    Only ``name = expression`` is considered.  We keep the expression text so
    later assignments can reference earlier names without executing user code.
    """

    result: dict[str, str] = {}
    try:
        tree = ast.parse(source or "")
    except SyntaxError:
        return result
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            expr = ast.get_source_segment(source, node.value) or ast.unparse(node.value)
        except Exception:
            continue
        # Store only expressions composed of arithmetic/name/int nodes. Unknown
        # names are fine; calls/attributes are not treated as allocator sizes.
        try:
            parsed = ast.parse(expr, mode="eval")
        except SyntaxError:
            continue
        if any(isinstance(item, (ast.Call, ast.Attribute, ast.Subscript, ast.Lambda, ast.Dict, ast.List, ast.Set)) for item in ast.walk(parsed)):
            continue
        result[target.id] = expr.strip()
    return result


def hex_size(value: int | None) -> str:
    return "未知" if value is None else hex(value)


def display_expr(value: str | int | None, default: str = "未知") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def safe_link_encode_expr(target: str, fd_storage: str) -> str:
    return f"({target}) ^ (({fd_storage}) >> 12)"
