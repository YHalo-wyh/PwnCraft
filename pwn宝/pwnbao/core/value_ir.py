"""ValueIR — value domain + call-site records for BinaryIR (VNext.2 M2.1).

Kinds (owner-locked):
  ARG(n)                       function parameter (position-based, name-free)
  CONST(v)                     immediate
  STACK_SLOT(off)              rbp-relative local
  GLOBAL(addr)                 absolute address (object table / bss)
  LOAD(base, index, scale, offset)   memory access: base[index*scale+offset]
  CALL_RESULT(callee, site)    return value of a specific call
  EXPR(op, operands)           arithmetic over ValueIRs
  UNKNOWN                      proven-insufficient evidence (never guessed)

Deterministic-First: every value records where it came from; nothing here
infers semantics beyond the instruction stream it was built from.

ObjectRef (M2.3): canonical identity of `base[index*scale]` slot accesses.
Identity = (base, scale, index-key) so `free(chunks[idx])` / `edit(chunks[idx])`
normalize to the same object regardless of parameter *names*.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

K_ARG = "arg"
K_CONST = "const"
K_STACK = "stack_slot"
K_GLOBAL = "global"
K_LOAD = "load"
K_CALL_RESULT = "call_result"
K_EXPR = "expr"
K_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ValueIR:
    kind: str
    n: int | None = None          # ARG position
    value: int | None = None      # CONST
    offset: int = 0               # STACK_SLOT / LOAD offset
    address: str = ""             # GLOBAL hex string
    base: "ValueIR | None" = None # LOAD base
    index: "ValueIR | None" = None  # LOAD index
    scale: int = 1                # LOAD scale
    callee: str = ""              # CALL_RESULT callee name
    site: str = ""                # CALL_RESULT call address
    op: str = ""                  # EXPR operator
    operands: tuple["ValueIR", ...] = ()
    reason: str = ""              # UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        if self.kind == K_ARG:
            out["n"] = self.n
        elif self.kind == K_CONST:
            out["value"] = self.value
        elif self.kind == K_STACK:
            out["offset"] = self.offset
        elif self.kind == K_GLOBAL:
            out["address"] = self.address
        elif self.kind == K_LOAD:
            out["base"] = self.base.to_dict() if self.base else None
            out["index"] = self.index.to_dict() if self.index else None
            out["scale"] = self.scale
            out["offset"] = self.offset
        elif self.kind == K_CALL_RESULT:
            out["callee"] = self.callee
            out["site"] = self.site
        elif self.kind == K_EXPR:
            out["op"] = self.op
            out["operands"] = [o.to_dict() for o in self.operands]
        else:
            out["reason"] = self.reason
        return out

    # -- identity keys (M2.3)
    def index_key(self) -> str:
        """Stable identity of an index value (name-free, position-based)."""
        if self.kind == K_ARG:
            return f"ARG{self.n}"
        if self.kind == K_CONST:
            return f"CONST{self.value}"
        if self.kind == K_STACK:
            return f"STACK{self.offset}"
        if self.kind == K_GLOBAL:
            return f"GLOBAL{self.address}"
        if self.kind == K_CALL_RESULT:
            return f"CALL:{self.callee}@{self.site}"
        if self.kind == K_EXPR:
            return f"EXPR({self.op},{','.join(o.index_key() for o in self.operands)})"
        return "UNKNOWN"

    def describe(self) -> str:
        if self.kind == K_ARG:
            return f"ARG({self.n})"
        if self.kind == K_CONST:
            return f"CONST({self.value:#x})" if self.value is not None else "CONST(?)"
        if self.kind == K_STACK:
            return f"STACK_SLOT({self.offset:#x})"
        if self.kind == K_GLOBAL:
            return f"GLOBAL({self.address})"
        if self.kind == K_LOAD:
            return (f"LOAD({self.base.describe() if self.base else '?'}, "
                    f"{self.index.describe() if self.index else '?'}, "
                    f"scale={self.scale}, off={self.offset:#x})")
        if self.kind == K_CALL_RESULT:
            return f"CALL_RESULT({self.callee}@{self.site})"
        if self.kind == K_EXPR:
            return f"EXPR({self.op}, {[o.describe() for o in self.operands]})"
        return "UNKNOWN"


@dataclass(frozen=True)
class ObjectRef:
    """Canonical slot identity: base[index*scale] (M2.3)."""
    base: str            # GLOBAL address hex
    index_key: str       # ValueIR.index_key()
    scale: int = 8

    def to_dict(self) -> dict[str, Any]:
        return {"base": self.base, "index_key": self.index_key, "scale": self.scale}


@dataclass(frozen=True)
class CallSiteIR:
    """One call site with recovered argument ValueIRs (M2.2)."""
    address: str
    function: str             # containing function name
    callee: str               # resolved callee symbol (malloc/read/...)
    args: tuple[ValueIR, ...]
    result: ValueIR | None = None
    span_start: str = ""
    span_end: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "function": self.function,
            "callee": self.callee,
            "args": [a.to_dict() for a in self.args],
            "result": self.result.to_dict() if self.result else None,
        }


@dataclass(frozen=True)
class StoreIR:
    """A memory store: slot := value (STORE_PTR / CLEAR_PTR evidence base)."""
    address: str
    function: str
    slot: ObjectRef | None     # when the target resolves to a table slot
    target: ValueIR            # full target ValueIR (may be FIELD(base, off))
    value: ValueIR
    line_address: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address, "function": self.function,
            "slot": self.slot.to_dict() if self.slot else None,
            "target": self.target.to_dict(),
            "value": self.value.to_dict(),
            "line_address": self.line_address,
        }
