"""Parsers that turn readelf/objdump stdout into structured symbol facts.

All functions follow the same contract as the gadget parser: they only
accept the exact line shapes these tools emit, so arbitrary text cannot
become a fabricated fact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re


_DYNSYM_LINE_RE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+\w+\s+\w+\s+(\S+)\s+(\S.*?)\s*$"
)


@dataclass(frozen=True)
class SymbolFacts:
    """Structured result of one dynamic-symbol scan."""

    functions: dict[str, int] = field(default_factory=dict)
    imports: tuple[str, ...] = ()
    objects: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "functions": dict(self.functions),
            "imports": list(self.imports),
            "objects": dict(self.objects),
        }


def parse_readelf_dynsyms(text: str) -> SymbolFacts:
    """Parse ``readelf -sW`` output.

    Defined FUNC entries become ``functions[name] = offset address``; UND
    entries become imports.  Version suffixes such as ``puts@GLIBC_2.2.5``
    are stripped from the lookup key but preserved in nothing else, because
    this model only records addresses it can point at.
    """
    functions: dict[str, int] = {}
    objects: dict[str, int] = {}
    imports: list[str] = []
    for raw_line in str(text).splitlines():
        match = _DYNSYM_LINE_RE.match(raw_line)
        if not match:
            continue
        raw_address, _size, kind, index, name_field = match.groups()
        name = name_field.split("@")[0].strip()
        if not name or name.startswith("$"):
            continue
        try:
            address = int(raw_address, 16)
        except ValueError:
            continue
        upper_kind = kind.upper()
        undefined = index.upper() == "UND"
        if undefined:
            imports.append(name)
            continue
        if upper_kind == "FUNC":
            functions.setdefault(name, address)
        elif upper_kind == "OBJECT":
            objects.setdefault(name, address)
    return SymbolFacts(functions, tuple(imports), objects)


_RELOC_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+(R_\S+)\s+(\S.*?)\s*$")
_PLT_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>@\s]+)@plt>:\s*$")


def parse_objdump_relocations(text: str) -> dict[str, int]:
    """Parse ``objdump -R`` into ``got[name] = slot address``.

    Both GLOB_DAT and JUMP_SLOT entries land in the GOT; the value is the
    raw relocation OFFSET, which is what CTF payloads need.
    """
    got: dict[str, int] = {}
    for raw_line in str(text).splitlines():
        match = _RELOC_LINE_RE.match(raw_line)
        if not match:
            continue
        raw_offset, reloc_type, value_field = match.groups()
        symbol = value_field.split("@")[0].strip()
        if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", symbol):
            continue
        if "GLOB_DAT" not in reloc_type and "JUMP_SLOT" not in reloc_type:
            continue
        try:
            got[symbol] = int(raw_offset, 16)
        except ValueError:
            continue
    return got


def parse_objdump_plt(text: str) -> dict[str, int]:
    """Parse ``objdump -d -j .plt`` into ``plt[name] = stub address``."""
    plt: dict[str, int] = {}
    for raw_line in str(text).splitlines():
        match = _PLT_LINE_RE.match(raw_line)
        if not match:
            continue
        try:
            plt[match.group(2)] = int(match.group(1), 16)
        except ValueError:
            continue
    return plt
