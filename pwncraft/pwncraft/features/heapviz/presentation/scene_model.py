from __future__ import annotations

import re
from dataclasses import dataclass

from pwncraft.features.heapviz.expressions import parse_int_expr
from pwncraft.features.heapviz.models import ChunkState, HeapSnapshot, ValueObservation


_OFFSET_RE = re.compile(r"(?:^|\+)\s*(0x[0-9a-fA-F]+|\d+)\s*$")


@dataclass(frozen=True)
class HeapSceneLayout:
    heap_x: float = 24.0
    heap_y: float = 64.0
    heap_width: float = 680.0
    bin_x: float = 740.0
    bin_y: float = 24.0
    bin_width: float = 720.0
    column_gap: float = 36.0

    @classmethod
    def for_heap_width(cls, heap_width: float, heap_x: float = 24.0) -> HeapSceneLayout:
        gap = 36.0
        return cls(heap_x, 64.0, heap_width, heap_x + heap_width + gap, 24.0, 720.0, gap)


@dataclass(frozen=True)
class PhysicalChunkGroup:
    group_id: str
    chunks: tuple[ChunkState, ...]
    start: int | None
    end: int | None
    overlap: bool = False
    full_cover: bool = False
    physical_object_ids: tuple[str, ...] = ()
    shared_memory: bool = False


@dataclass(frozen=True)
class HeapSceneModel:
    layout: HeapSceneLayout
    groups: tuple[PhysicalChunkGroup, ...]
    external_chunks: tuple[ChunkState, ...]
    observations: tuple[ValueObservation, ...]
    bin_rows: tuple[tuple[str, str, tuple[str, ...], bool], ...]


def build_heap_scene_model(snapshot: HeapSnapshot, layout: HeapSceneLayout | None = None) -> HeapSceneModel:
    layout = layout or HeapSceneLayout()
    heap_chunks: list[ChunkState] = []
    external: list[ChunkState] = []
    for chunk in snapshot.chunks.values():
        (heap_chunks if _is_heap_resident(chunk, snapshot) else external).append(chunk)
    ordered = sorted(enumerate(heap_chunks), key=lambda pair: _address_sort_key(pair[1], pair[0]))
    groups: list[PhysicalChunkGroup] = []
    current: list[ChunkState] = []
    current_start: int | None = None
    current_end: int | None = None

    def flush() -> None:
        nonlocal current, current_start, current_end
        if not current:
            return
        ranges = [_chunk_range(item) for item in current]
        concrete = [item for item in ranges if item is not None]
        full_cover = len(concrete) > 1 and all(item == concrete[0] for item in concrete[1:])
        groups.append(PhysicalChunkGroup(
            f"group_{len(groups) + 1:04d}",
            tuple(current),
            current_start,
            current_end,
            len(current) > 1,
            full_cover,
            tuple(dict.fromkeys(item.physical_id or item.chunk_id for item in current)),
            len(current) > 1,
        ))
        current = []
        current_start = None
        current_end = None

    for _fallback, chunk in ordered:
        chunk_range = _chunk_range(chunk)
        if not current:
            current = [chunk]
            if chunk_range:
                current_start, current_end = chunk_range
            continue
        consolidated = chunk.role == "consolidated" or any(item.role == "consolidated" for item in current)
        joins = bool(chunk_range and current_end is not None and (
            chunk_range[0] < current_end or (consolidated and chunk_range[0] <= current_end)
        ))
        if not joins:
            flush()
            current = [chunk]
            if chunk_range:
                current_start, current_end = chunk_range
            continue
        current.append(chunk)
        current_start = min(current_start if current_start is not None else chunk_range[0], chunk_range[0])
        current_end = max(current_end, chunk_range[1])
    flush()

    rows: list[tuple[str, str, tuple[str, ...], bool]] = []
    for title, mapping, doubly in (
        ("tcache", snapshot.bins.tcache, False),
        ("fastbins", snapshot.bins.fastbins, False),
        ("smallbins", snapshot.bins.smallbins, True),
        ("largebins", snapshot.bins.largebins, True),
    ):
        rows.extend((title, str(size), tuple(chain), doubly) for size, chain in mapping.items())
    if snapshot.bins.unsorted:
        rows.append(("unsorted", "arena", tuple(snapshot.bins.unsorted), True))
    return HeapSceneModel(layout, tuple(groups), tuple(external), tuple(snapshot.observations), tuple(rows))


def _is_heap_resident(chunk: ChunkState, snapshot: HeapSnapshot) -> bool:
    if chunk.heap_offset:
        return True
    address = (chunk.address or "").strip().replace(" ", "")
    base = (snapshot.heap_base or "heap_base").strip().replace(" ", "") or "heap_base"
    if address == base or address.startswith(base + "+"):
        return True
    base_value = parse_int_expr(base)
    address_value = parse_int_expr(address)
    return bool(base_value is not None and address_value is not None and base_value <= address_value < base_value + 0x1000000)


def _address_sort_key(chunk: ChunkState, fallback: int) -> tuple[int, int, int]:
    chunk_range = _chunk_range(chunk)
    return (0, chunk_range[0], fallback) if chunk_range else (1, fallback, fallback)


def _chunk_range(chunk: ChunkState) -> tuple[int, int] | None:
    start = parse_int_expr(chunk.heap_offset)
    if start is None:
        address = (chunk.address or "").strip().replace(" ", "")
        start = parse_int_expr(address)
        if start is None:
            match = _OFFSET_RE.search(address)
            start = parse_int_expr(match.group(1)) if match else None
    if start is None:
        return None
    size = parse_int_expr(chunk.chunk_size)
    return start, start + max(1, size or 1)
