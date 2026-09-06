from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Mapping

from pwncraft.features.heapviz.expressions import parse_int_expr


@dataclass(frozen=True, order=True)
class MemoryAddress:
    """An address in one concrete or symbolic address space.

    ``root == ""`` denotes an absolute integer address.  Symbolic heap/libc/
    stack roots retain a signed byte offset, so ``heap_base+0x290`` and
    ``heap_base+0x2a0`` can participate in exact interval operations without a
    fabricated runtime base.
    """

    root: str
    offset: int = 0
    expression: str = ""

    @property
    def concrete(self) -> bool:
        return not self.root

    @property
    def value(self) -> int | None:
        return self.offset if self.concrete else None

    @property
    def space(self) -> str:
        return self.root or "@absolute"

    def add(self, delta: int) -> MemoryAddress:
        return MemoryAddress(self.root, self.offset + int(delta), self.expression)

    def distance_to(self, other: MemoryAddress) -> int | None:
        if self.space != other.space:
            return None
        return other.offset - self.offset

    def format(self) -> str:
        if self.concrete:
            return hex(self.offset)
        if self.offset == 0:
            return self.root
        sign = "+" if self.offset > 0 else "-"
        return f"{self.root}{sign}0x{abs(self.offset):x}"

    def __str__(self) -> str:
        return self.format()

    @classmethod
    def parse(
        cls,
        value: MemoryAddress | str | int,
        variables: Mapping[str, str | int] | None = None,
    ) -> MemoryAddress:
        if isinstance(value, MemoryAddress):
            return value
        if isinstance(value, int):
            return cls("", value, hex(value))
        source = str(value or "").strip()
        if not source:
            raise ValueError("empty memory address")
        concrete = parse_int_expr(source, variables)
        if concrete is not None:
            return cls("", concrete, source)

        compact = re.sub(r"\s+", "", source)
        affine = _parse_affine(compact, variables or {}, frozenset())
        if affine is not None:
            root, offset = affine
            if root:
                return cls(root, offset, source)

        # Preserve complex targets such as ``libc.sym['environ']-0x10`` as a
        # stable root plus a trailing literal offset when possible.
        match = re.fullmatch(r"(?P<root>.+?)(?P<sign>[+-])(?P<num>0x[0-9a-fA-F]+|\d+)", compact)
        if match and match.group("root"):
            delta = int(match.group("num"), 0)
            if match.group("sign") == "-":
                delta = -delta
            return cls(match.group("root"), delta, source)
        return cls(compact, 0, source)


def _parse_affine(
    source: str,
    variables: Mapping[str, str | int],
    seen: frozenset[str],
) -> tuple[str, int] | None:
    try:
        node = ast.parse(source, mode="eval").body
    except SyntaxError:
        return None

    def visit(item: ast.AST) -> tuple[str, int] | None:
        if isinstance(item, ast.Constant) and isinstance(item.value, int):
            return "", int(item.value)
        if isinstance(item, ast.Name):
            if item.id in variables and item.id not in seen:
                nested = str(variables[item.id]).strip()
                resolved = parse_int_expr(nested, variables)
                if resolved is not None:
                    return "", resolved
            return item.id, 0
        if isinstance(item, ast.UnaryOp) and isinstance(item.op, (ast.UAdd, ast.USub)):
            value = visit(item.operand)
            if value is None or value[0]:
                return None
            return "", value[1] if isinstance(item.op, ast.UAdd) else -value[1]
        if isinstance(item, ast.BinOp) and isinstance(item.op, (ast.Add, ast.Sub)):
            left, right = visit(item.left), visit(item.right)
            if left is None or right is None:
                return None
            sign = 1 if isinstance(item.op, ast.Add) else -1
            if left[0] and right[0]:
                return None
            if right[0] and sign < 0:
                return None
            return (left[0] or right[0], left[1] + sign * right[1])
        return None

    return visit(node)
