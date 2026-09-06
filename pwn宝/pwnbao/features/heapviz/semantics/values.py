from __future__ import annotations

import ast
import operator
from dataclasses import dataclass
from typing import Mapping, TypeAlias


@dataclass(frozen=True)
class UnknownValue:
    reason: str = "not statically provable"
    source: str = ""

    @property
    def concrete(self) -> bool:
        return False


@dataclass(frozen=True)
class ConcreteInt:
    value: int
    source: str = ""

    @property
    def concrete(self) -> bool:
        return True


@dataclass(frozen=True)
class SymbolicInt:
    expression: str
    dependencies: tuple[str, ...] = ()

    @property
    def concrete(self) -> bool:
        return False


@dataclass(frozen=True)
class LengthExpr(SymbolicInt):
    """An integer expression known to denote a byte length."""


@dataclass(frozen=True)
class PointerExpr(SymbolicInt):
    address_space: str = "unknown"


@dataclass(frozen=True)
class ConcreteBytes:
    value: bytes
    source: str = ""

    @property
    def length(self) -> ConcreteInt:
        return ConcreteInt(len(self.value), f"len({self.source})" if self.source else "")

    @property
    def concrete(self) -> bool:
        return True


@dataclass(frozen=True)
class SymbolicBytes:
    expression: str
    byte_length: ConcreteInt | LengthExpr | UnknownValue
    spans: tuple[tuple[int | str, int | str, str], ...] = ()
    dependencies: tuple[str, ...] = ()

    @property
    def concrete(self) -> bool:
        return False


AbstractValue: TypeAlias = (
    ConcreteInt | SymbolicInt | ConcreteBytes | SymbolicBytes | LengthExpr | PointerExpr | UnknownValue
)


_INTEGER_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
}
_INTEGER_SYMBOLS = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.FloorDiv: "//",
    ast.Mod: "%",
    ast.LShift: "<<",
    ast.RShift: ">>",
    ast.BitAnd: "&",
    ast.BitOr: "|",
    ast.BitXor: "^",
}


def evaluate_value(source: str, environment: Mapping[str, AbstractValue | int | bytes | str] | None = None) -> AbstractValue:
    """Safely evaluate the static value/length subset used by heap EXPs.

    User source is parsed as AST and is never executed.  Unsupported calls are
    represented structurally instead of being guessed.
    """

    text = str(source or "").strip()
    if not text:
        return UnknownValue("empty expression", text)
    try:
        node = ast.parse(text, mode="eval").body
    except SyntaxError:
        return UnknownValue("syntax error", text)
    env = {name: _coerce(value, name) for name, value in dict(environment or {}).items()}
    return _eval(node, env, text)


def byte_length(value: AbstractValue) -> ConcreteInt | LengthExpr | UnknownValue:
    if isinstance(value, ConcreteBytes):
        return value.length
    if isinstance(value, SymbolicBytes):
        return value.byte_length
    return UnknownValue("value has no byte length", render_value(value))


def render_value(value: AbstractValue) -> str:
    if isinstance(value, ConcreteInt):
        return hex(value.value) if value.value >= 10 else str(value.value)
    if isinstance(value, ConcreteBytes):
        return repr(value.value)
    if isinstance(value, (SymbolicInt, SymbolicBytes)):
        return value.expression
    return value.source or "UNKNOWN"


def _coerce(value: AbstractValue | int | bytes | str, source: str = "") -> AbstractValue:
    if isinstance(value, (ConcreteInt, SymbolicInt, ConcreteBytes, SymbolicBytes, UnknownValue)):
        return value
    if isinstance(value, int):
        return ConcreteInt(value, source)
    if isinstance(value, bytes):
        return ConcreteBytes(value, source)
    if isinstance(value, str):
        return SymbolicInt(value, (source,) if source else ())
    return UnknownValue("unsupported environment value", source)


def _eval(node: ast.AST, env: Mapping[str, AbstractValue], source: str = "") -> AbstractValue:
    rendered = source or _unparse(node)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return ConcreteInt(int(node.value), rendered)
        if isinstance(node.value, int):
            return ConcreteInt(node.value, rendered)
        if isinstance(node.value, bytes):
            return ConcreteBytes(node.value, rendered)
        if isinstance(node.value, str):
            return ConcreteBytes(node.value.encode(), rendered)
        return UnknownValue("unsupported literal", rendered)
    if isinstance(node, ast.Name):
        return env.get(node.id, SymbolicInt(node.id, (node.id,)))
    if isinstance(node, ast.UnaryOp):
        value = _eval(node.operand, env)
        if isinstance(value, ConcreteInt):
            try:
                if isinstance(node.op, ast.USub):
                    return ConcreteInt(-value.value, rendered)
                if isinstance(node.op, ast.UAdd):
                    return ConcreteInt(+value.value, rendered)
                if isinstance(node.op, ast.Invert):
                    return ConcreteInt(~value.value, rendered)
            except ArithmeticError:
                pass
        return SymbolicInt(rendered, _dependencies(value))
    if isinstance(node, ast.BinOp):
        left = _eval(node.left, env)
        right = _eval(node.right, env)
        if isinstance(node.op, ast.Add) and _is_bytes(left) and _is_bytes(right):
            return _concat_bytes(left, right, rendered)
        if isinstance(node.op, ast.Mult):
            if _is_bytes(left) and _is_int(right):
                return _repeat_bytes(left, right, rendered)
            if _is_int(left) and _is_bytes(right):
                return _repeat_bytes(right, left, rendered)
        if _is_int(left) and _is_int(right):
            operation = _INTEGER_BINOPS.get(type(node.op))
            if operation and isinstance(left, ConcreteInt) and isinstance(right, ConcreteInt):
                try:
                    return ConcreteInt(operation(left.value, right.value), rendered)
                except (ArithmeticError, ValueError):
                    return UnknownValue("invalid integer operation", rendered)
            if type(node.op) in _INTEGER_SYMBOLS:
                deps = tuple(dict.fromkeys((*_dependencies(left), *_dependencies(right))))
                cls = PointerExpr if isinstance(left, PointerExpr) or isinstance(right, PointerExpr) else SymbolicInt
                return cls(rendered, deps)
        return UnknownValue("unsupported binary value types", rendered)
    if isinstance(node, ast.Call):
        name = _qualified_name(node.func)
        short = name.rsplit(".", 1)[-1]
        arguments = [_eval(item, env) for item in node.args]
        if short == "len" and len(arguments) == 1:
            length = byte_length(arguments[0])
            if isinstance(length, ConcreteInt):
                return ConcreteInt(length.value, rendered)
            if isinstance(length, LengthExpr):
                return LengthExpr(length.expression, length.dependencies)
            return LengthExpr(f"len({_unparse(node.args[0])})", _dependencies(arguments[0]))
        widths = {"p8": 1, "p16": 2, "p32": 4, "p64": 8, "u32": 4, "u64": 8}
        if short in widths:
            if short.startswith("u"):
                return SymbolicInt(rendered, _join_dependencies(arguments))
            return SymbolicBytes(rendered, ConcreteInt(widths[short], f"sizeof({short})"), dependencies=_join_dependencies(arguments))
        if short == "pack" or name == "struct.pack":
            width = _struct_pack_width(node.args[0]) if node.args else None
            length: ConcreteInt | UnknownValue = ConcreteInt(width, "struct format") if width is not None else UnknownValue("dynamic struct format", rendered)
            return SymbolicBytes(rendered, length, dependencies=_join_dependencies(arguments))
        if short in {"flat", "fit"}:
            return _flat_value(node, arguments, rendered)
        if short in {"bytes", "bytearray"}:
            if not arguments:
                return ConcreteBytes(b"", rendered)
            item = arguments[0]
            if isinstance(item, ConcreteInt) and item.value >= 0:
                return ConcreteBytes(bytes(item.value), rendered)
            if _is_bytes(item):
                return SymbolicBytes(rendered, byte_length(item), dependencies=_dependencies(item))
        if short in {"ljust", "rjust"} and arguments:
            receiver_node = node.func.value if isinstance(node.func, ast.Attribute) else None
            receiver = _eval(receiver_node, env) if receiver_node is not None else UnknownValue()
            width = arguments[0]
            if isinstance(width, ConcreteInt):
                return SymbolicBytes(rendered, ConcreteInt(max(0, width.value), rendered), dependencies=_join_dependencies((receiver, *arguments)))
            return SymbolicBytes(rendered, LengthExpr(rendered, _join_dependencies((receiver, *arguments))))
        if short == "to_bytes" and isinstance(node.func, ast.Attribute) and arguments:
            width = arguments[0]
            length = width if isinstance(width, ConcreteInt) else LengthExpr(render_value(width), _dependencies(width))
            return SymbolicBytes(rendered, length, dependencies=_join_dependencies(arguments))
        if short in {"address_of", "addressof"}:
            return PointerExpr(rendered, _join_dependencies(arguments))
        return UnknownValue("unsupported call", rendered)
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [_eval(item, env) for item in node.elts]
        if all(_is_bytes(item) for item in values):
            result: AbstractValue = ConcreteBytes(b"", rendered)
            for item in values:
                result = _concat_bytes(result, item, rendered)
            return result
    if isinstance(node, ast.Subscript):
        value = _eval(node.value, env)
        if _is_bytes(value) and isinstance(node.slice, ast.Slice):
            start = _literal_int(node.slice.lower, 0)
            stop = _literal_int(node.slice.upper, None)
            step = _literal_int(node.slice.step, 1)
            if isinstance(value, ConcreteBytes) and step is not None:
                return ConcreteBytes(value.value[slice(start, stop, step)], rendered)
            if step == 1 and start is not None and stop is not None:
                return SymbolicBytes(rendered, ConcreteInt(max(0, stop - start), rendered), dependencies=_dependencies(value))
            return SymbolicBytes(rendered, UnknownValue("symbolic slice length", rendered), dependencies=_dependencies(value))
    return UnknownValue("unsupported expression", rendered)


def _flat_value(node: ast.Call, arguments: list[AbstractValue], rendered: str) -> AbstractValue:
    if node.args and isinstance(node.args[0], ast.Dict):
        spans: list[tuple[int | str, int | str, str]] = []
        maximum = 0
        concrete = True
        for key_node, value_node in zip(node.args[0].keys, node.args[0].values):
            if key_node is None:
                concrete = False
                continue
            offset_value = _eval(key_node, {})
            item = _eval(value_node, {})
            length = byte_length(item)
            start: int | str = offset_value.value if isinstance(offset_value, ConcreteInt) else render_value(offset_value)
            end: int | str
            if isinstance(start, int) and isinstance(length, ConcreteInt):
                end = start + length.value
                maximum = max(maximum, end)
            else:
                concrete = False
                end = f"({start})+({render_value(length)})"
            spans.append((start, end, _unparse(value_node)))
        length_value: ConcreteInt | LengthExpr = ConcreteInt(maximum, rendered) if concrete else LengthExpr(f"sparse_extent({rendered})", _join_dependencies(arguments))
        return SymbolicBytes(rendered, length_value, tuple(spans), _join_dependencies(arguments))
    total: ConcreteInt | LengthExpr | UnknownValue = ConcreteInt(0, rendered)
    for item in arguments:
        total = _add_lengths(total, byte_length(item))
    return SymbolicBytes(rendered, total, dependencies=_join_dependencies(arguments))


def _concat_bytes(left: AbstractValue, right: AbstractValue, rendered: str) -> AbstractValue:
    if isinstance(left, ConcreteBytes) and isinstance(right, ConcreteBytes):
        return ConcreteBytes(left.value + right.value, rendered)
    length = _add_lengths(byte_length(left), byte_length(right))
    return SymbolicBytes(rendered, length, dependencies=tuple(dict.fromkeys((*_dependencies(left), *_dependencies(right)))))


def _repeat_bytes(value: AbstractValue, count: AbstractValue, rendered: str) -> AbstractValue:
    if isinstance(value, ConcreteBytes) and isinstance(count, ConcreteInt) and count.value >= 0:
        return ConcreteBytes(value.value * count.value, rendered)
    length = byte_length(value)
    if isinstance(length, ConcreteInt) and isinstance(count, ConcreteInt):
        return ConcreteBytes(b"", rendered) if count.value < 0 else SymbolicBytes(rendered, ConcreteInt(length.value * count.value, rendered), dependencies=_join_dependencies((value, count)))
    return SymbolicBytes(rendered, LengthExpr(f"({render_value(length)})*({render_value(count)})", _join_dependencies((value, count))), dependencies=_join_dependencies((value, count)))


def _add_lengths(left: ConcreteInt | LengthExpr | UnknownValue, right: ConcreteInt | LengthExpr | UnknownValue) -> ConcreteInt | LengthExpr | UnknownValue:
    if isinstance(left, ConcreteInt) and isinstance(right, ConcreteInt):
        return ConcreteInt(left.value + right.value)
    if isinstance(left, UnknownValue) or isinstance(right, UnknownValue):
        return UnknownValue("length operand unknown", f"{render_value(left)}+{render_value(right)}")
    return LengthExpr(f"({render_value(left)})+({render_value(right)})", tuple(dict.fromkeys((*_dependencies(left), *_dependencies(right)))))


def _dependencies(value: AbstractValue) -> tuple[str, ...]:
    return getattr(value, "dependencies", ())


def _join_dependencies(values: object) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:  # type: ignore[union-attr]
        for dependency in _dependencies(value):
            if dependency not in result:
                result.append(dependency)
    return tuple(result)


def _is_int(value: AbstractValue) -> bool:
    return isinstance(value, (ConcreteInt, SymbolicInt))


def _is_bytes(value: AbstractValue) -> bool:
    return isinstance(value, (ConcreteBytes, SymbolicBytes))


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _literal_int(node: ast.AST | None, default: int | None) -> int | None:
    if node is None:
        return default
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    return None


def _struct_pack_width(node: ast.AST) -> int | None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, (str, bytes)):
        return None
    import struct

    try:
        return struct.calcsize(node.value)
    except (struct.error, TypeError):
        return None


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""
