from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pwnbao.features.heapviz.expressions import parse_int_expr
from pwnbao.features.heapviz.memory import MemoryAddress, WriteKind
from pwnbao.features.heapviz.models import ChunkState, HeapSnapshot


class VisualKind(Enum):
    BASE = "base"
    CROSS_WRITE = "cross_write"
    PHYSICAL_OVERLAP = "physical_overlap"
    INVALID_MARK = "invalid_mark"


class PhysicalViewRelationKind(Enum):
    ACTIVE_ALIAS = "active_alias"
    NORMAL_REUSE = "normal_reuse"
    STALE_VIEW = "stale_view"
    CORRUPTION_OVERLAP = "corruption_overlap"


@dataclass(frozen=True)
class PhysicalViewRelation:
    left_object: str
    right_object: str
    physical_start: str
    physical_end: str
    kind: PhysicalViewRelationKind
    evidence: str = ""


@dataclass(frozen=True)
class PaintSpan:
    object_id: str
    field: str
    physical_start: str
    physical_end: str
    visual_kind: VisualKind
    owner: str = ""
    writer: str = ""
    byte_start: int = 0
    byte_end: int = 0

    @property
    def byte_length(self) -> int:
        return max(0, self.byte_end - self.byte_start)


@dataclass(frozen=True)
class HeapVisualModel:
    spans: tuple[PaintSpan, ...]
    relations: tuple[PhysicalViewRelation, ...]


class HeapVisualModelBuilder:
    """Current-truth classifier. It never reads attack names or overwrite history."""

    def build(self, snapshot: HeapSnapshot) -> HeapVisualModel:
        spans: list[PaintSpan] = []
        for chunk in snapshot.chunks.values():
            start, end = _chunk_range(chunk)
            if start is None or end is None:
                continue
            spans.append(PaintSpan(
                chunk.chunk_id,
                "chunk",
                start.format(),
                end.format(),
                VisualKind.BASE,
                owner=chunk.chunk_id,
                byte_start=0,
                byte_end=max(0, end.offset - start.offset),
            ))

        # Cross-write colour is a CURRENT MEMORY property, not a property of
        # the operation that happened to produce this snapshot.  The engine
        # stamps cross-object writes into PhysicalMemory provenance, so a later
        # SHOW/NOTE/malloc that does not touch those bytes must not erase the
        # colour.  Conversely, when the owner rewrites the bytes, the current
        # provenance changes and the colour disappears naturally.
        chunks_by_physical = {
            (chunk.physical_id or chunk.chunk_id): chunk
            for chunk in snapshot.chunks.values()
        }
        for memory_span in snapshot.memory.spans:
            provenance = memory_span.provenance
            if provenance.write_kind is not WriteKind.CROSS_CHUNK_OVERWRITE:
                continue
            owner_id = provenance.owner_at_write
            owner_chunk = chunks_by_physical.get(owner_id)
            if owner_chunk is None:
                # A stale historical owner is not enough to paint the current
                # canvas.  Only a current logical view may own a coloured span.
                continue
            target_field = provenance.target_field or "physical"
            field_offset = max(0, int(provenance.target_field_offset or 0))
            spans.append(PaintSpan(
                # object_id 必须是物理实体 id：前端按 physical_id 匹配 span。
                # chunk_id（菜单标签）会随分配 generation 漂移，不能当画布 key。
                owner_chunk.physical_id or owner_chunk.chunk_id,
                target_field,
                memory_span.start.format(),
                memory_span.end.format(),
                VisualKind.CROSS_WRITE,
                owner=owner_chunk.chunk_id,
                writer=provenance.writer_object_id or provenance.writer,
                byte_start=field_offset,
                byte_end=field_offset + memory_span.length,
            ))

        # Legacy scene compatibility only: old schema snapshots may have event
        # edges but no PhysicalMemory spans/provenance.  New snapshots never
        # use the current operation event as the truth source for colour.
        if not snapshot.memory.spans:
            for edge in snapshot.overwrite_edges:
                try:
                    start = MemoryAddress.parse(edge.physical_start)
                    end = MemoryAddress.parse(edge.physical_end)
                except ValueError:
                    continue
                if start.space != end.space or end.offset <= start.offset:
                    continue
                field_offset = max(0, int(edge.target_field_offset or 0))
                spans.append(PaintSpan(
                    edge.target_physical_object or edge.target_chunk,
                    edge.target_field,
                    start.format(),
                    end.format(),
                    VisualKind.CROSS_WRITE,
                    owner=edge.target_chunk,
                    writer=edge.source_chunk or edge.writer_operation,
                    byte_start=field_offset,
                    byte_end=field_offset + (end.offset - start.offset),
                ))

        relations = classify_physical_relations(snapshot)
        for relation in relations:
            if relation.kind is not PhysicalViewRelationKind.CORRUPTION_OVERLAP:
                continue
            start, end = MemoryAddress.parse(relation.physical_start), MemoryAddress.parse(relation.physical_end)
            for object_id, owner in ((relation.left_object, relation.right_object), (relation.right_object, relation.left_object)):
                spans.append(PaintSpan(
                    object_id,
                    "physical",
                    start.format(),
                    end.format(),
                    VisualKind.PHYSICAL_OVERLAP,
                    owner=owner,
                    byte_start=0,
                    byte_end=end.offset - start.offset,
                ))
        if snapshot.aborted and snapshot.allocator_abort:
            spans.append(PaintSpan(
                snapshot.allocator_abort.address or "allocator",
                snapshot.allocator_abort.check,
                snapshot.allocator_abort.address,
                snapshot.allocator_abort.address,
                VisualKind.INVALID_MARK,
                writer=snapshot.operation_id,
            ))
        return HeapVisualModel(tuple(spans), relations)


def classify_physical_relations(snapshot: HeapSnapshot) -> tuple[PhysicalViewRelation, ...]:
    chunks = list(snapshot.chunks.values())
    cross_ranges: list[tuple[MemoryAddress, MemoryAddress, str]] = []
    for span in snapshot.memory.spans:
        provenance = span.provenance
        if provenance.write_kind is WriteKind.CROSS_CHUNK_OVERWRITE:
            cross_ranges.append((span.start, span.end, provenance.writer_object_id or provenance.writer))
    if not snapshot.memory.spans:  # legacy scene fallback only
        for edge in snapshot.overwrite_edges:
            try:
                left, right = MemoryAddress.parse(edge.physical_start), MemoryAddress.parse(edge.physical_end)
            except ValueError:
                continue
            cross_ranges.append((left, right, edge.source_chunk or edge.writer_operation))
    # Sweep sorted physical intervals. The old nested loop reparsed every
    # address/size O(n²), making ordinary 100-chunk snapshots noticeably laggy
    # even though adjacent non-overlapping chunks have no relation. The sweep
    # remains O(n²) only for the genuinely pathological case where all views
    # overlap, which is exactly when all pairs must be emitted.
    parsed: list[tuple[int, ChunkState, MemoryAddress, MemoryAddress]] = []
    for index, chunk in enumerate(chunks):
        start, end = _chunk_range(chunk)
        if start is not None and end is not None:
            parsed.append((index, chunk, start, end))
    parsed.sort(key=lambda item: (item[2].space, item[2].offset, item[3].offset, item[0]))
    relations_with_order: list[tuple[int, int, PhysicalViewRelation]] = []
    active: list[tuple[int, ChunkState, MemoryAddress, MemoryAddress]] = []
    current_space = None
    for current in parsed:
        current_index, current_chunk, current_start, current_end = current
        if current_start.space != current_space:
            active = []
            current_space = current_start.space
        active = [item for item in active if item[3].offset > current_start.offset]
        for previous_index, previous_chunk, previous_start, previous_end in active:
            if previous_index < current_index:
                left_index, left_chunk, left_start, left_end = (
                    previous_index, previous_chunk, previous_start, previous_end
                )
                right_index, right_chunk, right_start, right_end = (
                    current_index, current_chunk, current_start, current_end
                )
            else:
                left_index, left_chunk, left_start, left_end = (
                    current_index, current_chunk, current_start, current_end
                )
                right_index, right_chunk, right_start, right_end = (
                    previous_index, previous_chunk, previous_start, previous_end
                )
            start = max(left_start.offset, right_start.offset)
            end = min(left_end.offset, right_end.offset)
            if end <= start:
                continue
            physical_start = MemoryAddress(left_start.root, start).format()
            physical_end = MemoryAddress(left_start.root, end).format()
            corrupting = next((writer for a, b, writer in cross_ranges if a.space == left_start.space and a.offset < end and b.offset > start), "")
            # A stale logical view and its new allocator owner are normal
            # lifetime reuse even when some current bytes retain cross-write
            # provenance.  Those exact bytes are already painted by
            # CROSS_WRITE spans; recolouring the whole stale/new intersection
            # would incorrectly present normal replacement as overlap.
            if _is_normal_reuse(left_chunk, right_chunk):
                kind = PhysicalViewRelationKind.NORMAL_REUSE
                evidence = "allocator lifetime reuse"
            elif corrupting:
                kind = PhysicalViewRelationKind.CORRUPTION_OVERLAP
                evidence = f"current cross-object write: {corrupting}"
            elif left_chunk.physical_id and left_chunk.physical_id == right_chunk.physical_id:
                kind = PhysicalViewRelationKind.ACTIVE_ALIAS
                evidence = "same current physical object"
            elif _is_current_owner(left_chunk) and _is_current_owner(right_chunk):
                kind = PhysicalViewRelationKind.CORRUPTION_OVERLAP
                evidence = "two distinct current physical owners claim intersecting bytes"
            else:
                kind = PhysicalViewRelationKind.STALE_VIEW
                evidence = "overlapping logical view without current corruption proof"
            relations_with_order.append((left_index, right_index, PhysicalViewRelation(
                left_chunk.chunk_id,
                right_chunk.chunk_id,
                physical_start,
                physical_end,
                kind,
                evidence,
            )))
        active.append(current)
    relations_with_order.sort(key=lambda item: (item[0], item[1]))
    return tuple(item[2] for item in relations_with_order)


def _is_normal_reuse(left: ChunkState, right: ChunkState) -> bool:
    """Return true only for allocator-proven reuse of one physical lineage.

    Merely seeing one inactive view and one active view whose ranges intersect
    is not enough: a corrupted chunksize can create exactly that geometry.
    The engine deliberately preserves ``physical_id`` when malloc reuses a
    freed physical allocation, so equality is the required allocator evidence.
    """
    inactive = {"freed", "released", "reused", "stale", "dangling"}
    active = {"allocated", "active", "inuse"}
    states = {left.lifecycle.lower(), right.lifecycle.lower()}
    same_lineage = bool(left.physical_id and right.physical_id and left.physical_id == right.physical_id)
    return same_lineage and bool(states & inactive and states & active)


def _is_current_owner(chunk: ChunkState) -> bool:
    return chunk.lifecycle.lower() not in {"freed", "released", "reused", "stale", "dangling"}


def _chunk_range(chunk: ChunkState) -> tuple[MemoryAddress | None, MemoryAddress | None]:
    size = parse_int_expr(chunk.chunk_size)
    if size is None or size <= 0:
        return None, None
    address = chunk.address or chunk.heap_offset
    if not address:
        return None, None
    try:
        start = MemoryAddress.parse(address)
    except ValueError:
        return None, None
    return start, start.add(size)
