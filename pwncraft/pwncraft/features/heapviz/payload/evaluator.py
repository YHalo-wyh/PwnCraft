from __future__ import annotations

import ast
import struct
from dataclasses import dataclass
from typing import Any, Mapping

from pwncraft.features.heapviz.expressions import parse_int_expr
from pwncraft.features.heapviz.payload.ir import PayloadIR


@dataclass(frozen=True)
class _Symbolic:
    expression: str


class PayloadEvaluator:
    """Safe AST evaluator that recovers byte offsets without executing EXP."""

    def __init__(
        self,
        *,
        bits: int = 64,
        variables: Mapping[str, str | int] | None = None,
        max_length: int = 0x100000,
    ):
        self.bits = 64 if bits == 64 else 32
        self.word_size = self.bits // 8
        self.variables = dict(variables or {})
        self.max_length = max(0x1000, int(max_length))
        self._seen: set[str] = set()

    def evaluate(self, expression: str | bytes | bytearray) -> PayloadIR:
        if isinstance(expression, (bytes, bytearray)):
            return PayloadIR.from_bytes(bytes(expression))
        source = str(expression or "").strip()
        if not source:
            return PayloadIR.from_bytes(b"", source)
        try:
            node = ast.parse(source, mode="eval").body
        except SyntaxError:
            return PayloadIR.unknown(source, "payload expression has invalid Python syntax")
        value = self._eval(node)
        return self._as_payload(value, node, source)

    def _eval(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bytes):
                return PayloadIR.from_bytes(node.value, _unparse(node))
            if isinstance(node.value, str):
                return PayloadIR.from_bytes(node.value.encode(), _unparse(node))
            if isinstance(node.value, (int, bool)):
                return int(node.value)
            return _Symbolic(_unparse(node))
        if isinstance(node, ast.Name):
            if node.id not in self.variables or node.id in self._seen:
                return _Symbolic(node.id)
            value = self.variables[node.id]
            if isinstance(value, int):
                return value
            self._seen.add(node.id)
            try:
                try:
                    nested = ast.parse(str(value), mode="eval").body
                except SyntaxError:
                    return _Symbolic(node.id)
                return self._eval(nested)
            finally:
                self._seen.discard(node.id)
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self._eval(item) for item in node.elts]
        if isinstance(node, ast.Dict):
            result: dict[int, Any] = {}
            for key, value in zip(node.keys, node.values):
                offset = self._int(self._eval(key)) if key is not None else None
                if offset is None or offset < 0:
                    return _Symbolic(_unparse(node))
                result[offset] = self._eval(value)
            return result
        if isinstance(node, ast.UnaryOp):
            value = self._int(self._eval(node.operand))
            if value is None:
                return _Symbolic(_unparse(node))
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.UAdd):
                return value
            if isinstance(node.op, ast.Invert):
                return ~value
            return _Symbolic(_unparse(node))
        if isinstance(node, ast.BinOp):
            left, right = self._eval(node.left), self._eval(node.right)
            if isinstance(node.op, ast.Add):
                if self._payload_like(left) or self._payload_like(right):
                    return self._as_payload(left, node.left).concat(self._as_payload(right, node.right), _unparse(node))
                left_int, right_int = self._int(left), self._int(right)
                return left_int + right_int if left_int is not None and right_int is not None else _Symbolic(_unparse(node))
            if isinstance(node.op, ast.Mult):
                if self._payload_like(left) and self._int(right) is not None:
                    return self._as_payload(left, node.left).repeat(self._int(right) or 0, _unparse(node))
                if self._payload_like(right) and self._int(left) is not None:
                    return self._as_payload(right, node.right).repeat(self._int(left) or 0, _unparse(node))
            left_int, right_int = self._int(left), self._int(right)
            if left_int is not None and right_int is not None:
                try:
                    if isinstance(node.op, ast.Sub):
                        return left_int - right_int
                    if isinstance(node.op, ast.Mult):
                        return left_int * right_int
                    if isinstance(node.op, ast.LShift):
                        return left_int << right_int
                    if isinstance(node.op, ast.RShift):
                        return left_int >> right_int
                    if isinstance(node.op, ast.BitAnd):
                        return left_int & right_int
                    if isinstance(node.op, ast.BitOr):
                        return left_int | right_int
                    if isinstance(node.op, ast.BitXor):
                        return left_int ^ right_int
                except (ArithmeticError, ValueError, OverflowError):
                    pass
            return _Symbolic(_unparse(node))
        if isinstance(node, ast.Subscript):
            value = self._eval(node.value)
            if isinstance(node.slice, ast.Slice) and self._payload_like(value):
                lower = self._int(self._eval(node.slice.lower)) if node.slice.lower else 0
                upper = self._int(self._eval(node.slice.upper)) if node.slice.upper else self._as_payload(value, node.value).length
                if lower is not None and upper is not None:
                    return self._as_payload(value, node.value).slice(lower, upper, _unparse(node))
            return _Symbolic(_unparse(node))
        if isinstance(node, ast.Call):
            return self._call(node)
        return _Symbolic(_unparse(node))

    def _call(self, node: ast.Call) -> Any:
        name = _call_name(node.func)
        if name in {"p8", "p16", "p32", "p64"} and node.args:
            size = int(name[1:]) // 8
            value = self._eval(node.args[0])
            integer = self._int(value)
            expression = _unparse(node)
            if integer is not None:
                mask = (1 << (size * 8)) - 1
                return PayloadIR.from_bytes(int(integer & mask).to_bytes(size, "little"), expression)
            inner = value.expression if isinstance(value, _Symbolic) else _unparse(node.args[0])
            return PayloadIR.symbolic(f"{name}({inner})", size)
        if name in {"flat", "fit"}:
            return self._flat(node)
        if name in {"bytes", "bytearray"}:
            return self._bytes_call(node)
        if name == "struct.pack" and node.args:
            return self._struct_pack(node)
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            base = self._eval(node.func.value)
            if method in {"ljust", "rjust"} and self._payload_like(base) and node.args:
                payload = self._as_payload(base, node.func.value)
                width = self._int(self._eval(node.args[0]))
                fill = self._as_payload(self._eval(node.args[1]), node.args[1]).materialize() if len(node.args) > 1 else b" "
                if width is not None and payload.length is not None and width <= self.max_length and fill and len(fill) == 1:
                    padding = max(0, width - payload.length)
                    pad = PayloadIR.from_bytes(fill * padding, repr(fill * padding))
                    return payload.concat(pad, _unparse(node)) if method == "ljust" else pad.concat(payload, _unparse(node))
            if method == "to_bytes" and node.args:
                integer = self._int(base)
                length = self._int(self._eval(node.args[0]))
                endian = "little"
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    endian = node.args[1].value
                if length is not None and 0 <= length <= self.max_length:
                    if integer is not None:
                        mask = (1 << (length * 8)) - 1 if length else 0
                        return PayloadIR.from_bytes(int(integer & mask).to_bytes(length, endian), _unparse(node))
                    return PayloadIR.symbolic(_unparse(node), length, endian=endian)
            if method == "join" and node.args:
                separator = self._as_payload(base, node.func.value)
                values = self._eval(node.args[0])
                if isinstance(values, list):
                    result = PayloadIR.from_bytes(b"", _unparse(node))
                    for index, item in enumerate(values):
                        if index:
                            result = result.concat(separator)
                        result = result.concat(self._as_payload(item, node.args[0]))
                    return PayloadIR(_unparse(node), result.segments, result.length, result.confidence, result.diagnostics)
        return _Symbolic(_unparse(node))

    def _flat(self, node: ast.Call) -> PayloadIR:
        values = [self._eval(item) for item in node.args]
        if len(values) == 1 and isinstance(values[0], list):
            values = values[0]
        if len(values) == 1 and isinstance(values[0], dict):
            result = PayloadIR(_unparse(node), (), 0)
            for offset, value in sorted(values[0].items()):
                result = result.overlay(self._flat_item(value, node), offset=offset, expression=_unparse(node))
            filler: bytes | None = None
            target_length: int | None = None
            for keyword in node.keywords:
                if keyword.arg == "filler":
                    filler_payload = self._as_payload(self._eval(keyword.value), keyword.value)
                    filler = filler_payload.materialize()
                    if filler is not None and len(filler) != 1:
                        filler = None
                elif keyword.arg == "length":
                    target_length = self._int(self._eval(keyword.value))
            return result.fill_gaps(raw_fill=filler, target_length=target_length)
        result = PayloadIR.from_bytes(b"", _unparse(node))
        for value in values:
            result = result.concat(self._flat_item(value, node), _unparse(node))
        return result

    def _flat_item(self, value: Any, node: ast.AST) -> PayloadIR:
        integer = self._int(value)
        if integer is not None and not self._payload_like(value):
            mask = (1 << self.bits) - 1
            return PayloadIR.from_bytes(int(integer & mask).to_bytes(self.word_size, "little"), _unparse(node))
        if isinstance(value, _Symbolic):
            return PayloadIR.symbolic(f"p{self.bits}({value.expression})", self.word_size)
        return self._as_payload(value, node)

    def _bytes_call(self, node: ast.Call) -> PayloadIR:
        if not node.args:
            return PayloadIR.from_bytes(b"", _unparse(node))
        value = self._eval(node.args[0])
        integer = self._int(value)
        if integer is not None and 0 <= integer <= self.max_length:
            return PayloadIR.from_bytes(b"\x00" * integer, _unparse(node))
        if isinstance(value, list):
            integers = [self._int(item) for item in value]
            if all(item is not None and 0 <= item <= 255 for item in integers):
                return PayloadIR.from_bytes(bytes(int(item) for item in integers), _unparse(node))
        return self._as_payload(value, node)

    def _struct_pack(self, node: ast.Call) -> PayloadIR:
        if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
            return PayloadIR.unknown(_unparse(node))
        fmt = node.args[0].value
        values = [self._eval(item) for item in node.args[1:]]
        integers = [self._int(item) for item in values]
        try:
            size = struct.calcsize(fmt)
        except struct.error:
            return PayloadIR.unknown(_unparse(node), "invalid struct.pack format")
        if all(item is not None for item in integers):
            try:
                return PayloadIR.from_bytes(struct.pack(fmt, *(int(item) for item in integers)), _unparse(node))
            except (struct.error, OverflowError):
                pass
        return PayloadIR.symbolic(_unparse(node), size, endian="little" if fmt[:1] in {"<", "=", "@"} else "big")

    def _as_payload(self, value: Any, node: ast.AST, expression: str = "") -> PayloadIR:
        if isinstance(value, PayloadIR):
            return value
        if isinstance(value, bytes):
            return PayloadIR.from_bytes(value, expression or _unparse(node))
        if isinstance(value, str):
            return PayloadIR.from_bytes(value.encode(), expression or _unparse(node))
        if isinstance(value, _Symbolic):
            return PayloadIR.unknown(value.expression)
        if isinstance(value, int):
            return PayloadIR.symbolic(expression or _unparse(node), self.word_size)
        return PayloadIR.unknown(expression or _unparse(node))

    @staticmethod
    def _payload_like(value: Any) -> bool:
        return isinstance(value, (PayloadIR, bytes, str))

    def _int(self, value: Any) -> int | None:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, _Symbolic):
            return parse_int_expr(value.expression, self.variables)
        return None


def collect_payload_assignments(source: str) -> dict[str, str]:
    """Collect payload builders without executing the EXP.

    Augmented assignments are folded into a source expression so a later
    ``edit(0, payload)`` retains the exact concatenation offsets.
    """
    try:
        tree = ast.parse(source or "")
    except SyntaxError:
        return {}
    result: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name):
            if _looks_payload_node(statement.value):
                result[statement.targets[0].id] = ast.get_source_segment(source, statement.value) or _unparse(statement.value)
        elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name) and isinstance(statement.op, ast.Add):
            name = statement.target.id
            if name in result and _looks_payload_node(statement.value):
                right = ast.get_source_segment(source, statement.value) or _unparse(statement.value)
                result[name] = f"({result[name]}) + ({right})"
    return result


def _looks_payload_node(node: ast.AST) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.Constant) and isinstance(item.value, (bytes, bytearray)):
            return True
        if isinstance(item, ast.Call) and _call_name(item.func) in {
            "p8", "p16", "p32", "p64", "flat", "fit", "bytes", "bytearray", "struct.pack"
        }:
            return True
    return False


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return "unknown"
