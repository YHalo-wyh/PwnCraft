from __future__ import annotations

from dataclasses import dataclass

from pwnbao.features.heapviz.memory import MemoryAddress, PhysicalMemorySnapshot


@dataclass(frozen=True)
class ArenaLink:
    """One pointer read from an allocator-owned virtual arena bin head."""

    field: str
    address: MemoryAddress
    value: str


class BinHeadView:
    """Typed fd/bk view over a virtual arena region in PhysicalMemory."""

    def __init__(self, memory: PhysicalMemorySnapshot, address: str, word_size: int):
        self.memory = memory
        self.address = MemoryAddress.parse(address)
        self.word_size = word_size

    def _link(self, field: str, offset: int) -> ArenaLink:
        address = self.address.add(offset)
        read = self.memory.read(address, self.word_size)
        if read.data is not None:
            integer = int.from_bytes(read.data, "little")
            value = "NULL" if integer == 0 else hex(integer)
        else:
            value = read.symbolic or "unknown"
        return ArenaLink(field, address, value)

    @property
    def fd(self) -> ArenaLink:
        return self._link("fd", 0)

    @property
    def bk(self) -> ArenaLink:
        return self._link("bk", self.word_size)


__all__ = ["ArenaLink", "BinHeadView"]
