"""Libc Workspace facts (Phase 4, 规划 §二十五/§二十六).

one_gadget output is parsed into structured records; constraints are checked
only against registers the runtime actually reported.  Anything that needs
memory (``rsp+0x40 == NULL``) or unknown registers stays ``unknown`` and the
gadget is never advertised as usable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re


_ADDR_RE = re.compile(r"^(0x[0-9a-fA-F]+)\s+(execve|system|.*?\(.*?)\s*$")
_CONSTRAINT_RE = re.compile(r"^\[?\d*\]?\s*([A-Za-z0-9_]+(?:\s*\+\s*0x[0-9a-fA-F]+)?)\s*==\s*(NULL|0)\s*$", re.IGNORECASE)


@dataclass
class OneGadget:
    address: int
    call: str
    constraints: tuple[str, ...] = ()
    label: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"address": self.address, "call": self.call, "constraints": list(self.constraints), "label": self.label}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "OneGadget":
        raw = payload.get("address", 0)
        return cls(int(raw, 0) if isinstance(raw, str) else int(raw), str(payload.get("call", "")), tuple(str(c) for c in payload.get("constraints", ())), str(payload.get("label", "")))


def parse_one_gadget_output(text: str) -> tuple[OneGadget, ...]:
    """Parse the standard one_gadget listing; unverifiable input stays out."""
    results: list[OneGadget] = []
    current: OneGadget | None = None
    in_constraints = False
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _ADDR_RE.match(line)
        if match and not line.lower().startswith("constraints"):
            current = OneGadget(int(match.group(1), 16), match.group(2).strip(), (), "")
            results.append(current)
            in_constraints = False
            continue
        if line.lower().startswith("constraints"):
            in_constraints = True
            continue
        if current is not None and in_constraints:
            if line.startswith("["):
                # Bracketed lines stay constraints; unsupported forms (memory
                # expressions, masks) are evaluated as unknown at check time.
                current.constraints += (line,)
            else:
                in_constraints = False
    return tuple(results)


@dataclass
class ConstraintReport:
    satisfied: tuple[str, ...] = ()
    violated: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        """A gadget is usable only when every constraint is provably met."""
        return bool(self.satisfied) and not self.violated and not self.unknown

    def to_dict(self) -> dict[str, object]:
        return {"satisfied": list(self.satisfied), "violated": list(self.violated), "unknown": list(self.unknown), "usable": self.usable}


def check_one_gadget_constraints(gadget: OneGadget, registers: dict[str, object] | None) -> ConstraintReport:
    """Evaluate ``reg == NULL`` style constraints against runtime registers.

    Only register facts count.  Missing registers and memory expressions
    (``rsp+0x40``) are unknown — the check never guesses memory content.
    """
    report = ConstraintReport()
    if not gadget.constraints:
        report.satisfied = ("(无约束)",)
        return report
    known = {str(key).lower(): value for key, value in (registers or {}).items()}
    for constraint in gadget.constraints:
        match = _CONSTRAINT_RE.match(constraint)
        if match is None:
            report.unknown += (constraint,)
            continue
        expression = re.sub(r"\s+", "", match.group(1)).lower()
        if "+" in expression:
            # Memory dereference/register-offset facts need a runtime oracle.
            report.unknown += (constraint,)
            continue
        if expression not in known:
            report.unknown += (constraint,)
            continue
        value = known[expression]
        if value == 0 or value == "0":
            report.satisfied += (constraint,)
        else:
            report.violated += (constraint,)
    return report


def parse_build_id(text: str) -> str:
    """Extract the Build ID from ``readelf -n`` output; empty when absent."""
    for raw_line in str(text).splitlines():
        match = re.search(r"Build ID:\s*([0-9a-fA-F]{8,64})", raw_line)
        if match:
            return match.group(1)
    return ""
