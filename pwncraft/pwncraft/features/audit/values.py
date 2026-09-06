"""Symbolic Value Domain (VNext.3.1 #4, Deterministic-First).

A closed value lattice for EXP/heap reasoning:

    CONCRETE  exact int (from literal / constant propagation)
    SYMBOL    named-but-unknown int (user input, runtime leak) — carries a
              derivation tag, never guessed
    EXPR      unevaluated expression string over symbols
    RANGE     bounded interval [lo, hi]
    UNKNOWN   proven-insufficient evidence (explicit; never a guess)

Deterministic-First: only CONCRETE values may drive exact state transitions
(e.g. heap index resolution); anything else degrades to UNKNOWN events.
No probabilistic inference enters this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ValueKind(Enum):
    CONCRETE = "concrete"
    SYMBOL = "symbol"
    EXPR = "expr"
    RANGE = "range"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SymbolicValue:
    kind: ValueKind
    value: Optional[int] = None          # CONCRETE
    name: str = ""                       # SYMBOL (derivation provenance tag)
    expression: str = ""                 # EXPR
    lo: Optional[int] = None             # RANGE
    hi: Optional[int] = None             # RANGE
    reason: str = ""                     # UNKNOWN

    # -- constructors
    @staticmethod
    def concrete(value: int) -> "SymbolicValue":
        return SymbolicValue(ValueKind.CONCRETE, value=value)

    @staticmethod
    def symbol(name: str, derivation: str = "user_input") -> "SymbolicValue":
        return SymbolicValue(ValueKind.SYMBOL, name=name, reason=derivation)

    @staticmethod
    def expr(expression: str) -> "SymbolicValue":
        return SymbolicValue(ValueKind.EXPR, expression=expression)

    @staticmethod
    def range(lo: int, hi: int) -> "SymbolicValue":
        return SymbolicValue(ValueKind.RANGE, lo=lo, hi=hi)

    @staticmethod
    def unknown(reason: str = "insufficient evidence") -> "SymbolicValue":
        return SymbolicValue(ValueKind.UNKNOWN, reason=reason)

    # -- predicates
    def is_concrete(self) -> bool:
        return self.kind is ValueKind.CONCRETE

    def as_int(self) -> Optional[int]:
        return self.value if self.is_concrete() else None

    # -- lattice join (merge two views of the same slot)
    def join(self, other: "SymbolicValue") -> "SymbolicValue":
        if self.kind is ValueKind.UNKNOWN:
            return other
        if other.kind is ValueKind.UNKNOWN:
            return self
        if self == other:
            return self
        if self.is_concrete() and other.is_concrete():
            lo, hi = min(self.value, other.value), max(self.value, other.value)
            return SymbolicValue.range(lo, hi)
        if self.kind is ValueKind.RANGE and other.is_concrete():
            return SymbolicValue.range(min(self.lo, other.value),
                                       max(self.hi, other.value))
        if other.kind is ValueKind.RANGE and self.is_concrete():
            return other.join(self)
        if self.kind is ValueKind.EXPR and other.kind is ValueKind.EXPR:
            return SymbolicValue.expr(self.expression) if \
                self.expression == other.expression else \
                SymbolicValue.unknown(f"join({self.expression}, {other.expression})")
        return SymbolicValue.unknown(f"join({self.describe()}, {other.describe()})")

    def describe(self) -> str:
        if self.kind is ValueKind.CONCRETE:
            return hex(self.value) if self.value is not None else "?"
        if self.kind is ValueKind.SYMBOL:
            return f"sym({self.name};{self.reason})"
        if self.kind is ValueKind.EXPR:
            return f"expr({self.expression})"
        if self.kind is ValueKind.RANGE:
            return f"range[{self.lo:#x},{self.hi:#x}]"
        return f"unknown({self.reason})"
