from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pwncraft.features.heapviz.memory import MemoryAddress
from pwncraft.features.heapviz.payload import PayloadIR


class WriteImpactKind(Enum):
    SELF_USER_WRITE = "self_user_write"
    SELF_METADATA_WRITE = "self_metadata_write"
    CROSS_OBJECT_WRITE = "cross_object_write"
    CROSS_CHUNK_OVERWRITE = "cross_chunk_overwrite"
    PARTIAL_FIELD_OVERWRITE = "partial_field_overwrite"
    FREELIST_METADATA_CORRUPTION = "freelist_metadata_corruption"
    TOP_METADATA_CORRUPTION = "top_metadata_corruption"
    ARENA_METADATA_WRITE = "arena_metadata_write"


@dataclass(frozen=True)
class WriteImpact:
    target_physical_object: str
    target_chunk: str
    target_field: str
    physical_start: MemoryAddress
    physical_end: MemoryAddress
    source_payload_offset: int
    before: str
    after: str
    confidence: str = "derived"
    kind: str = WriteImpactKind.CROSS_OBJECT_WRITE.value
    target_field_offset: int = 0
    target_field_length: int = 0
    source_payload_length: int = 0
    changed_byte_mask: str = ""


@dataclass(frozen=True)
class OverwriteEdge:
    writer_operation: str
    source_chunk: str
    source_pointer: str
    target_physical_object: str
    target_chunk: str
    target_field: str
    physical_start: str
    physical_end: str
    source_payload_offset: int
    before: str
    after: str
    confidence: str = "derived"
    kind: str = WriteImpactKind.CROSS_OBJECT_WRITE.value
    target_field_offset: int = 0
    target_field_length: int = 0
    source_payload_length: int = 0
    changed_byte_mask: str = ""


@dataclass(frozen=True)
class WriteEvent:
    event_id: str
    operation_id: str
    source_line: int
    source_expression: str
    base_pointer: str
    destination_address: str
    payload: PayloadIR
    length: int | None
    confidence: str = "derived"
    source_chunk: str = ""
    affected_regions: tuple[WriteImpact, ...] = ()
    overwritten_fields: tuple[str, ...] = ()
    writer: str = "program"


@dataclass(frozen=True)
class ReadEvent:
    event_id: str
    operation_id: str
    source_address: str
    length: int | None
    result: str = ""
    confidence: str = "derived"


@dataclass(frozen=True)
class AllocEvent:
    event_id: str
    operation_id: str
    chunk: str
    chunk_address: str
    user_pointer: str
    request_size: str
    chunk_size: str
    source: str = "top"
    # Allocation truth: the frontend only ever *trusts* snapshot.bins chains,
    # so every malloc must carry the evidence that the victim really was the
    # bin head it claims.  ``allocation_source`` is the normalized bin kind
    # (tcache/fastbin/smallbin/largebin/unsorted/top); the before/after heads
    # are the PhysicalMemory-derived chains the pop was validated against.
    allocation_source_kind: str = ""
    victim_physical_id: str = ""
    bin_head_before: tuple[str, ...] = ()
    bin_head_after: tuple[str, ...] = ()


@dataclass(frozen=True)
class FreeEvent:
    event_id: str
    operation_id: str
    chunk: str
    chunk_address: str
    destination_bin: str


@dataclass(frozen=True)
class BinTransitionEvent:
    """Allocator evidence for a freelist membership/link mutation."""

    event_id: str
    operation_id: str
    action: str
    bin_kind: str
    size: str
    node: str
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()
    moved_nodes: tuple[str, ...] = ()
    link_mutations: tuple[str, ...] = ()
    provenance: str = "derived"
    note: str = ""
