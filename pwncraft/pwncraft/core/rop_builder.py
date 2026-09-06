"""BUILD-side ROP chain construction (规划 §二十一/§二十二/§五十八).

The builder only assembles chains from gadgets with recorded evidence —
shelf gadgets first, then an optional discovered set.  It never invents an
address that no query tool produced.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .gadgets import Gadget, GadgetShelf
from .rop import AlignmentResult, ROPChain, ROPEntry

ARGUMENT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


@dataclass
class BuildReport:
    chain: ROPChain
    used_gadgets: dict[str, Gadget] = field(default_factory=dict)
    missing_registers: tuple[str, ...] = ()
    alignment: AlignmentResult | None = None
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Buildable: every requested register slot found a gadget."""
        return not self.missing_registers

    def to_dict(self) -> dict[str, object]:
        return {
            "chain": self.chain.to_dict(),
            "used_gadgets": {reg: item.to_dict() for reg, item in self.used_gadgets.items()},
            "missing_registers": list(self.missing_registers),
            "alignment": {
                "aligned": self.alignment.aligned,
                "rsp_mod_16": self.alignment.rsp_mod_16,
                "message": self.alignment.message,
                "suggested_ret": self.alignment.suggested_ret,
            }
            if self.alignment
            else None,
            "warnings": list(self.warnings),
        }


class RopChainBuilder:
    """Assemble call chains; shelf candidates always win over discovery."""

    def __init__(
        self,
        *,
        shelf: GadgetShelf | None = None,
        gadgets: Iterable[Gadget] = (),
        bits: int = 64,
    ):
        self.bits = int(bits)
        self.shelf = shelf or GadgetShelf()
        self.gadgets = tuple(gadgets)

    def _candidates_for(self, register: str) -> tuple[Gadget, ...]:
        pinned = self.shelf.get(register)
        others = tuple(
            gadget
            for gadget in self.gadgets
            if register in gadget.controls and not gadget.memory_side_effect and gadget.instructions[-1].lower().split()[0] == "ret"
        )
        others = tuple(sorted(others, key=lambda item: (-item.score, len(item.controls))))
        return ((pinned,) if pinned is not None else ()) + others

    def _ret_gadget(self) -> Gadget | None:
        pinned = self.shelf.get("ret")
        if pinned is not None:
            return pinned
        for gadget in self.gadgets:
            if tuple(part.strip().lower() for part in gadget.instructions) == ("ret",):
                return gadget
        return None

    def build_call(
        self,
        function: int | str,
        arguments: Mapping[object, object] | None = None,
        *,
        return_addr: int | str | None = None,
        check_alignment: bool = True,
    ) -> BuildReport:
        arguments = dict(arguments or {})
        chain = ROPChain(word_size=max(1, self.bits // 8))
        used: dict[str, Gadget] = {}
        missing: list[str] = []
        warnings: list[str] = []

        argument_registers: list[str] = []
        for key, value in arguments.items():
            if isinstance(key, str) and key.lower() in ARGUMENT_REGISTERS:
                argument_registers.append(key.lower())
            elif isinstance(key, int) and 0 <= key < len(ARGUMENT_REGISTERS):
                argument_registers.append(ARGUMENT_REGISTERS[key])
            else:
                warnings.append(f"未知参数槽位: {key!r}")
        argument_registers = [reg for reg in ARGUMENT_REGISTERS if reg in argument_registers]

        for register in argument_registers:
            candidates = self._candidates_for(register)
            if not candidates:
                missing.append(register)
                continue
            gadget = candidates[0]
            used[register] = gadget
            chain.append(gadget.address, kind="gadget", gadget=gadget)
            chain.append(arguments[[key for key in arguments if self._slot(key) == register][0]], kind="value")

        chain.append(function, kind="call")
        if return_addr is not None:
            chain.append(return_addr, kind="value")

        alignment = None
        if check_alignment and self.bits == 64:
            function_index = len(chain.entries) - (2 if return_addr is not None else 1)
            alignment = chain.check_alignment(before_entry=function_index)
            if not alignment.aligned:
                warnings.append(alignment.message + "；可自动插入 ret。")

        return BuildReport(chain, used, tuple(missing), alignment, tuple(warnings))

    @staticmethod
    def _slot(key: object) -> str | None:
        if isinstance(key, str) and key.lower() in ARGUMENT_REGISTERS:
            return key.lower()
        if isinstance(key, int) and 0 <= key < len(ARGUMENT_REGISTERS):
            return ARGUMENT_REGISTERS[key]
        return None

    def fix_alignment(self, report: BuildReport) -> BuildReport:
        """Insert one evidenced `ret` in front of the call (§二十二)."""
        if report.alignment is None or not report.alignment.suggested_ret:
            return report
        ret = self._ret_gadget()
        if ret is None:
            warnings = report.warnings + ("缺少可用 ret gadget；请先在 Gadget Explorer 收藏一个 ret。",)
            return BuildReport(report.chain, report.used_gadgets, report.missing_registers, report.alignment, warnings)
        chain = ROPChain(word_size=report.chain.word_size)
        chain.append(ret.address, kind="gadget", gadget=ret)
        for entry in report.chain.entries:
            offset = chain.entries[-1].offset + chain.word_size
            chain.entries.append(ROPEntry(offset, entry.value, entry.kind, entry.gadget))
        index = next(i for i, entry in enumerate(chain.entries) if entry.kind == "call")
        alignment = chain.check_alignment(before_entry=index)
        warnings = tuple(item for item in report.warnings if report.alignment is None or item != report.alignment.message + "；可自动插入 ret。")
        if alignment.aligned:
            return BuildReport(chain, {**report.used_gadgets, "ret": ret}, report.missing_registers, alignment, warnings)
        return BuildReport(chain, {**report.used_gadgets, "ret": ret}, report.missing_registers, alignment, warnings + (alignment.message + "；可自动插入 ret。",))


def chain_to_pwntools(
    chain: ROPChain,
    *,
    io_name: str = "io",
    payload_name: str = "payload",
    send: str = "sendline",
) -> str:
    """Emit an editable pwntools fragment; symbol strings pass through."""
    pack = "p64" if chain.word_size == 8 else "p32"
    lines = [f"{payload_name}  = b''"]
    for entry in chain.entries:
        if entry.gadget is not None:
            annotation = f"  # {entry.gadget.text}"
        elif entry.kind == "call":
            annotation = "  # call"
        else:
            annotation = ""
        if isinstance(entry.value, str):
            line = f"{payload_name} += {entry.value}"
        else:
            line = f"{payload_name} += {pack}({entry.value:#x})"
        lines.append(line + annotation)
    lines.append("")
    lines.append(f"{io_name}.{send}({payload_name})")
    return "\n".join(lines)
