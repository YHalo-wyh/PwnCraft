"""Sparse physical-memory truth model used by HeapViz.

The allocator and renderers intentionally share this layer.  A chunk, a fake
chunk and an overlapping alias are typed views over the same spans rather than
independent byte stores.
"""

from pwncraft.features.heapviz.memory.address import MemoryAddress
from pwncraft.features.heapviz.memory.physical_memory import (
    MemoryChange,
    MemoryObject,
    MemoryRead,
    MemorySpan,
    PhysicalMemory,
    PhysicalMemorySnapshot,
)
from pwncraft.features.heapviz.memory.provenance import MemoryProvenance, ProvenanceKind, WriteKind

__all__ = [
    "MemoryAddress",
    "MemoryChange",
    "MemoryObject",
    "MemoryProvenance",
    "MemoryRead",
    "MemorySpan",
    "PhysicalMemory",
    "PhysicalMemorySnapshot",
    "ProvenanceKind",
    "WriteKind",
]
