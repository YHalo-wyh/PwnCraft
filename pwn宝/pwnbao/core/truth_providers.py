from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct

from .gadgets import Gadget, parse_ropgadget_output
from .syscalls import parse_seccomp_policy
from .truth import TruthEvidence


class ELFProvider:
    name = "ELFProvider"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._facts = self._read_header()

    def _read_header(self) -> dict[str, object]:
        with self.path.open("rb") as stream:
            header = stream.read(64)
        if len(header) < 20 or header[:4] != b"\x7fELF":
            raise ValueError(f"不是有效 ELF: {self.path}")
        elf_class = {1: (32, "i386"), 2: (64, "amd64")}.get(header[4])
        if elf_class is None:
            raise ValueError(f"ELF class 不受支持: {header[4]}")
        endian = {1: "little", 2: "big"}.get(header[5])
        if endian is None:
            raise ValueError(f"ELF endian 不受支持: {header[5]}")
        order = "<" if endian == "little" else ">"
        entry_offset = 24
        entry_size = 4 if elf_class[0] == 32 else 8
        if len(header) < entry_offset + entry_size:
            raise ValueError(f"ELF header 截断: {self.path}")
        entry = struct.unpack_from(order + ("I" if entry_size == 4 else "Q"), header, entry_offset)[0]
        machine = struct.unpack_from(order + "H", header, 18)[0]
        architecture = {0x3E: "amd64", 0x03: "i386", 0xB7: "aarch64"}.get(machine, elf_class[1])
        return {"path": str(self.path), "bits": elf_class[0], "architecture": architecture, "endian": endian, "entry": entry, "machine": machine}

    def query(self, key: str, **_context: object) -> TruthEvidence | None:
        if key not in self._facts:
            return None
        return TruthEvidence(self._facts[key], self.name, f"ELF header: {key}", observed=True)


@dataclass
class GadgetProvider:
    output: str
    source: str = "ROPgadget"
    bits: int = 64
    base: int | None = None
    name: str = "GadgetProvider"

    def gadgets(self) -> tuple[Gadget, ...]:
        return parse_ropgadget_output(self.output, source=self.source, bits=self.bits, base=self.base)

    def query(self, key: str, **_context: object) -> TruthEvidence | None:
        gadgets = self.gadgets()
        if key in {"gadgets", "all"}:
            return TruthEvidence(gadgets, self.name, self.source, observed=True)
        matches = tuple(item for item in gadgets if key.casefold() in item.text.casefold() or key.casefold() in item.controls)
        return TruthEvidence(matches, self.name, f"{self.source}: {key}", observed=True) if matches else None


@dataclass
class SeccompProvider:
    policy_text: str
    name: str = "SeccompProvider"

    def policy(self) -> dict[str, str]:
        return parse_seccomp_policy(self.policy_text)

    def query(self, key: str, **_context: object) -> TruthEvidence | None:
        value = self.policy().get(str(key).lower())
        return TruthEvidence(value, self.name, f"seccomp policy: {key}", observed=True) if value else None
