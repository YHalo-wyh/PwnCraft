from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


# ROPgadget emits lines such as ``0x4012c3 : pop rdi ; ret``. Keep the
# parser strict so arbitrary command output cannot become a fabricated fact.
_GADGET_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+|[0-9]+)\s*:\s*(.*?)\s*$")
_POP_RE = re.compile(r"\bpop\s+([reap]?[a-z][a-z0-9]*)\b", re.IGNORECASE)
_KNOWN_REGISTERS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
}


@dataclass(frozen=True)
class Gadget:
    address: int
    instructions: tuple[str, ...]
    controls: tuple[str, ...] = ()
    clobbers: tuple[str, ...] = ()
    stack_delta: int = 0
    memory_side_effect: bool = False
    source: str = ""
    section: str = ""
    relative_offset: int | None = None
    score: int = 1
    evidence: str = ""

    @property
    def text(self) -> str:
        return " ; ".join(self.instructions)

    @property
    def stars(self) -> str:
        score = max(0, min(5, self.score))
        return "★" * score + "☆" * (5 - score)

    def to_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "instructions": list(self.instructions),
            "controls": list(self.controls),
            "clobbers": list(self.clobbers),
            "stack_delta": self.stack_delta,
            "memory_side_effect": self.memory_side_effect,
            "source": self.source,
            "section": self.section,
            "relative_offset": self.relative_offset,
            "score": self.score,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "Gadget":
        raw_address = payload.get("address", 0)
        address = int(raw_address, 0) if isinstance(raw_address, str) else int(raw_address)
        return cls(
            address=address,
            instructions=tuple(str(item) for item in payload.get("instructions", ())),
            controls=tuple(str(item).lower() for item in payload.get("controls", ())),
            clobbers=tuple(str(item).lower() for item in payload.get("clobbers", ())),
            stack_delta=int(payload.get("stack_delta", 0)),
            memory_side_effect=bool(payload.get("memory_side_effect", False)),
            source=str(payload.get("source", "")),
            section=str(payload.get("section", "")),
            relative_offset=(int(payload["relative_offset"]) if payload.get("relative_offset") is not None else None),
            score=int(payload.get("score", 1)),
            evidence=str(payload.get("evidence", "")),
        )


def parse_gadget_line(line: str, *, source: str = "", bits: int = 64, base: int | None = None) -> Gadget | None:
    match = _GADGET_RE.match(str(line))
    if not match:
        return None
    try:
        address = int(match.group(1), 0)
    except ValueError:
        return None
    text = match.group(2).strip()
    instructions = tuple(part.strip() for part in text.split(";") if part.strip())
    if not instructions:
        return None
    controls = tuple(reg.lower() for reg in _POP_RE.findall(text) if reg.lower() in _KNOWN_REGISTERS)
    # A multi-pop controls every popped register, but registers after the
    # first are caller-visible clobbers for a one-argument call.
    clobbers = controls[1:]
    word = max(1, int(bits) // 8)
    pops = len(controls)
    terminates_with_ret = instructions[-1].lower().split()[0] == "ret"
    stack_delta = (pops + (1 if terminates_with_ret else 0)) * word
    lowered = text.lower()
    memory_side_effect = any(token in lowered for token in ("[", "=", "xchg", "mov "))
    if len(controls) == 1 and terminates_with_ret and not memory_side_effect:
        score = 5
    elif len(controls) <= 2 and terminates_with_ret and not memory_side_effect:
        score = 4
    elif not memory_side_effect:
        score = 3 if len(controls) <= 2 else 2
    else:
        score = 1
    relative_offset = address - base if base is not None else None
    evidence = f"{address:#x} : {text}"
    return Gadget(address, instructions, controls, clobbers, stack_delta, memory_side_effect, source, "", relative_offset, score, evidence)


def parse_ropgadget_output(text: str, *, source: str = "", bits: int = 64, base: int | None = None) -> tuple[Gadget, ...]:
    result: list[Gadget] = []
    seen: set[tuple[int, str]] = set()
    for line in str(text).splitlines():
        gadget = parse_gadget_line(line, source=source, bits=bits, base=base)
        if gadget is None or (gadget.address, gadget.text) in seen:
            continue
        seen.add((gadget.address, gadget.text))
        result.append(gadget)
    return tuple(result)


def search_gadgets(gadgets: Iterable[Gadget], query: str) -> tuple[Gadget, ...]:
    needle = str(query).strip().casefold()
    if not needle:
        return tuple(gadgets)
    tokens = tuple(token for token in re.split(r"[ ,;]+", needle) if token)
    return tuple(item for item in gadgets if all(token in item.text.casefold() or token in item.controls for token in tokens))


@dataclass
class GadgetShelf:
    pinned: dict[str, Gadget]

    def __init__(self, pinned: dict[str, Gadget] | None = None) -> None:
        self.pinned = dict(pinned or {})

    def pin(self, role: str, gadget: Gadget) -> None:
        key = str(role).strip().lower()
        if not key:
            raise ValueError("Gadget 角色不能为空")
        self.pinned[key] = gadget

    def unpin(self, role: str) -> Gadget | None:
        return self.pinned.pop(str(role).strip().lower(), None)

    def get(self, role: str) -> Gadget | None:
        return self.pinned.get(str(role).strip().lower())

    def values(self) -> tuple[Gadget, ...]:
        return tuple(self.pinned.values())

    def to_dict(self) -> dict[str, object]:
        return {role: gadget.to_dict() for role, gadget in self.pinned.items()}

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "GadgetShelf":
        shelf = cls()
        for role, raw in payload.items():
            if isinstance(raw, dict):
                try:
                    shelf.pin(str(role), Gadget.from_dict(raw))
                except (TypeError, ValueError):
                    continue
        return shelf
