from __future__ import annotations

import ast
from dataclasses import dataclass


_BINOP_KINDS = {
    ast.Add: "add",
    ast.Sub: "sub",
    ast.Mult: "mul",
    ast.FloorDiv: "floor_div",
    ast.Mod: "mod",
    ast.LShift: "shift_left",
    ast.RShift: "shift_right",
    ast.BitAnd: "bit_and",
    ast.BitOr: "bit_or",
    ast.BitXor: "xor",
}


@dataclass(frozen=True)
class SemanticExpression:
    """A non-executable, typed view of an EXP expression.

    ``source`` remains the compatibility representation consumed by the current
    allocator.  ``kind`` and ``children`` preserve the AST meaning so analyzers,
    AI review and future allocators do not need to parse a formatted string back
    into structure.
    """

    kind: str
    source: str
    value: int | str | bytes | None = None
    name: str = ""
    children: tuple[SemanticExpression, ...] = ()

    @property
    def concrete_int(self) -> int | None:
        return self.value if self.kind == "concrete_int" and isinstance(self.value, int) else None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "source": self.source,
            "value": self.value,
            "name": self.name,
            "children": [child.to_dict() for child in self.children],
        }


def parse_semantic_expression(source: str) -> SemanticExpression:
    text = str(source or "").strip()
    if not text:
        return SemanticExpression("unknown", "")
    try:
        node = ast.parse(text, mode="eval").body
    except SyntaxError:
        return SemanticExpression("unknown", text)
    return _from_ast(node, text)


def _from_ast(node: ast.AST, source: str = "") -> SemanticExpression:
    rendered = source or _unparse(node)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return SemanticExpression("literal", rendered, node.value)
        if isinstance(node.value, int):
            return SemanticExpression("concrete_int", rendered, int(node.value))
        if isinstance(node.value, (str, bytes)):
            return SemanticExpression("bytes" if isinstance(node.value, bytes) else "string", rendered, node.value)
        return SemanticExpression("literal", rendered, node.value)
    if isinstance(node, ast.Name):
        return SemanticExpression("symbol", rendered, name=node.id)
    if isinstance(node, ast.Attribute):
        return SemanticExpression("attribute", rendered, name=_qualified_name(node))
    if isinstance(node, ast.BinOp):
        return SemanticExpression(
            _BINOP_KINDS.get(type(node.op), "binary"),
            rendered,
            children=(_from_ast(node.left), _from_ast(node.right)),
        )
    if isinstance(node, ast.UnaryOp):
        return SemanticExpression(
            {ast.USub: "negate", ast.UAdd: "positive", ast.Invert: "invert"}.get(type(node.op), "unary"),
            rendered,
            children=(_from_ast(node.operand),),
        )
    if isinstance(node, (ast.List, ast.Tuple)):
        return SemanticExpression(
            "byte_concat" if any(_looks_packed(item) for item in node.elts) else type(node).__name__.lower(),
            rendered,
            children=tuple(_from_ast(item) for item in node.elts),
        )
    if isinstance(node, ast.Call):
        name = _qualified_name(node.func)
        kind = "byte_concat" if name.rsplit(".", 1)[-1] in {"flat", "p8", "p16", "p32", "p64", "pack"} else "call"
        if name.rsplit(".", 1)[-1] in {"address_of", "addressof"}:
            kind = "address_of"
        children = tuple(_from_ast(item) for item in node.args) + tuple(_from_ast(item.value) for item in node.keywords)
        return SemanticExpression(kind, rendered, name=name, children=children)
    if isinstance(node, ast.Subscript):
        return SemanticExpression("subscript", rendered, children=(_from_ast(node.value), _from_ast(node.slice)))
    return SemanticExpression("unknown", rendered)


def _looks_packed(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _qualified_name(node.func).rsplit(".", 1)[-1] in {"flat", "p8", "p16", "p32", "p64", "pack"}


def _qualified_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""
