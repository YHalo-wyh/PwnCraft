from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, replace
from functools import cached_property
from typing import Iterable, Mapping

from pwnbao.features.heapviz.memory.address import MemoryAddress
from pwnbao.features.heapviz.memory.provenance import MemoryProvenance, ProvenanceKind


@dataclass(frozen=True)
class MemorySpan:
    start: MemoryAddress
    length: int
    data: bytes | None = None
    symbolic: str = ""
    state: str = "unknown"  # known | zero | unknown | metadata
    provenance: MemoryProvenance = MemoryProvenance()

    @property
    def end(self) -> MemoryAddress:
        return self.start.add(self.length)

    def slice(self, begin: int, end: int) -> MemorySpan:
        begin = max(0, begin)
        end = min(self.length, end)
        data = self.data[begin:end] if self.data is not None else None
        return replace(self, start=self.start.add(begin), length=max(0, end - begin), data=data)

    def display(self, endian: str = "little") -> str:
        if self.data is not None:
            if not self.data:
                return ""
            return hex(int.from_bytes(self.data, endian))
        return self.symbolic or "unknown"


@dataclass(frozen=True)
class MemoryObject:
    object_id: str
    start: MemoryAddress
    size: int
    kind: str = "region"
    label: str = ""
    provenance: str = "derived"

    @property
    def end(self) -> MemoryAddress:
        return self.start.add(self.size)


@dataclass(frozen=True)
class MemoryRead:
    start: MemoryAddress
    size: int
    spans: tuple[MemorySpan, ...]

    @property
    def data(self) -> bytes | None:
        if sum(item.length for item in self.spans) != self.size:
            return None
        if any(item.data is None for item in self.spans):
            return None
        return b"".join(item.data or b"" for item in self.spans)

    @property
    def symbolic(self) -> str:
        if len(self.spans) == 1 and self.spans[0].data is None:
            return self.spans[0].symbolic
        return ""

    @property
    def provenance(self) -> tuple[MemoryProvenance, ...]:
        return tuple(dict.fromkeys(item.provenance for item in self.spans))


@dataclass(frozen=True)
class MemoryChange:
    start: MemoryAddress
    length: int
    before: MemoryRead
    after: MemoryRead
    provenance: MemoryProvenance


@dataclass(frozen=True)
class PhysicalMemorySnapshot:
    spans: tuple[MemorySpan, ...] = ()
    objects: tuple[MemoryObject, ...] = ()

    @cached_property
    def _space_index(self) -> dict[str, tuple[tuple[int, ...], tuple[MemorySpan, ...]]]:
        grouped: dict[str, list[MemorySpan]] = {}
        for span in self.spans:
            grouped.setdefault(span.start.space, []).append(span)
        return {
            space: (tuple(item.start.offset for item in items), tuple(items))
            for space, items in grouped.items()
        }

    def read(self, address: MemoryAddress | str | int, size: int) -> MemoryRead:
        start = MemoryAddress.parse(address)
        return _read_from_index(self._space_index, start, size)

    def read_uint(self, address: MemoryAddress | str | int, size: int, endian: str = "little") -> int | None:
        data = self.read(address, size).data
        return int.from_bytes(data, endian) if data is not None else None

    def overlaps(self, start: MemoryAddress | str | int, end: MemoryAddress | str | int) -> tuple[MemoryObject, ...]:
        left, right = MemoryAddress.parse(start), MemoryAddress.parse(end)
        if left.space != right.space:
            return ()
        return tuple(
            item for item in self.objects
            if item.start.space == left.space and item.start.offset < right.offset and item.end.offset > left.offset
        )

    def get_provenance(self, address: MemoryAddress | str | int, size: int) -> tuple[MemoryProvenance, ...]:
        return self.read(address, size).provenance


class PhysicalMemory:
    """Sparse span-backed physical memory.

    A write splits only the touched intervals.  Unwritten holes stay implicit,
    so a large symbolic heap does not allocate one Python object per byte.
    """

    def __init__(self, variables: Mapping[str, str | int] | None = None):
        self.variables = dict(variables or {})
        self._spans: list[MemorySpan] = []
        self._objects: dict[str, MemoryObject] = {}
        self._index_cache: dict[str, tuple[tuple[int, ...], tuple[MemorySpan, ...]]] | None = None
        self._object_index_cache: dict[str, tuple[tuple[int, ...], tuple[int, ...], tuple[MemoryObject, ...]]] | None = None
        self._revision = 0
        self._object_revisions: dict[str, int] = {}
        self._address_cache: dict[str, MemoryAddress] = {}

    @classmethod
    def from_snapshot(
        cls,
        snapshot: PhysicalMemorySnapshot,
        variables: Mapping[str, str | int] | None = None,
    ) -> PhysicalMemory:
        memory = cls(variables)
        memory._spans = list(snapshot.spans)
        memory._objects = {item.object_id: item for item in snapshot.objects}
        memory._revision = len(memory._spans)
        memory._object_revisions = {item.object_id: memory._revision for item in snapshot.objects}
        return memory

    @property
    def spans(self) -> tuple[MemorySpan, ...]:
        return tuple(self._spans)

    @property
    def objects(self) -> tuple[MemoryObject, ...]:
        return tuple(self._objects.values())

    def address(self, value: MemoryAddress | str | int) -> MemoryAddress:
        if isinstance(value, MemoryAddress):
            return value
        key = str(value)
        cached = self._address_cache.get(key)
        if cached is None:
            cached = MemoryAddress.parse(value, self.variables)
            self._address_cache[key] = cached
        return cached

    def register_object(
        self,
        object_id: str,
        start: MemoryAddress | str | int,
        size: int,
        *,
        kind: str = "region",
        label: str = "",
        provenance: str = "derived",
    ) -> MemoryObject:
        item = MemoryObject(object_id, self.address(start), max(0, int(size)), kind, label, provenance)
        self._objects[object_id] = item
        self._object_revisions.setdefault(object_id, self._revision)
        self._object_index_cache = None
        return item

    def object_revision(self, object_id: str) -> int:
        return self._object_revisions.get(object_id, -1)

    def read(self, address: MemoryAddress | str | int, size: int) -> MemoryRead:
        if self._index_cache is None:
            grouped: dict[str, list[MemorySpan]] = {}
            for span in self._spans:
                grouped.setdefault(span.start.space, []).append(span)
            self._index_cache = {
                space: (tuple(item.start.offset for item in items), tuple(items))
                for space, items in grouped.items()
            }
        return _read_from_index(self._index_cache, self.address(address), size)

    def read_uint(self, address: MemoryAddress | str | int, size: int, endian: str = "little") -> int | None:
        data = self.read(address, size).data
        return int.from_bytes(data, endian) if data is not None else None

    def write_uint(
        self,
        address: MemoryAddress | str | int,
        value: int,
        size: int,
        provenance: MemoryProvenance,
        *,
        state: str = "metadata",
        endian: str = "little",
    ) -> tuple[MemoryChange, ...]:
        mask = (1 << (size * 8)) - 1
        return self.write(address, int(value & mask).to_bytes(size, endian), provenance, state=state)

    def write_symbolic(
        self,
        address: MemoryAddress | str | int,
        expression: str,
        size: int,
        provenance: MemoryProvenance,
        *,
        state: str = "known",
    ) -> tuple[MemoryChange, ...]:
        return self.write(address, None, provenance, length=size, symbolic=expression, state=state)

    def write(
        self,
        address: MemoryAddress | str | int,
        data: bytes | bytearray | None,
        provenance: MemoryProvenance,
        *,
        length: int | None = None,
        symbolic: str = "",
        state: str = "known",
    ) -> tuple[MemoryChange, ...]:
        start = self.address(address)
        raw = bytes(data) if data is not None else None
        size = len(raw) if raw is not None else int(length or 0)
        if size <= 0:
            return ()
        before = self.read(start, size)
        effective_state = "zero" if raw is not None and raw and not any(raw) and state == "known" else state
        replacement = MemorySpan(start, size, raw, symbolic, effective_state, provenance)
        kept: list[MemorySpan] = []
        write_end = start.offset + size
        for span in self._spans:
            if span.start.space != start.space or span.end.offset <= start.offset or span.start.offset >= write_end:
                kept.append(span)
                continue
            if span.start.offset < start.offset:
                kept.append(span.slice(0, start.offset - span.start.offset))
            if span.end.offset > write_end:
                kept.append(span.slice(write_end - span.start.offset, span.length))
        kept.append(replacement)
        self._spans = _merge_spans(sorted(kept, key=lambda item: (item.start.space, item.start.offset)))
        self._index_cache = None
        self._revision += 1
        for item in self._overlapping_objects(start, start.add(size)):
            self._object_revisions[item.object_id] = self._revision
        after = self.read(start, size)
        return (MemoryChange(start, size, before, after, provenance),)

    def slice(self, start: MemoryAddress | str | int, end: MemoryAddress | str | int) -> MemoryRead:
        left, right = self.address(start), self.address(end)
        if left.space != right.space or right.offset < left.offset:
            raise ValueError("memory slice crosses address spaces")
        return self.read(left, right.offset - left.offset)

    def overlaps(self, start: MemoryAddress | str | int, end: MemoryAddress | str | int) -> tuple[MemoryObject, ...]:
        return self._overlapping_objects(self.address(start), self.address(end))

    def get_provenance(self, address: MemoryAddress | str | int, size: int) -> tuple[MemoryProvenance, ...]:
        return self.read(address, size).provenance

    def snapshot(self) -> PhysicalMemorySnapshot:
        return PhysicalMemorySnapshot(tuple(self._spans), tuple(self._objects.values()))

    def restore(self, snapshot: PhysicalMemorySnapshot) -> None:
        """Restore the exact sparse-memory state in-place for semantic undo.

        Keeping the object identity is important because the allocator,
        correction history and UI may all hold the same ``PhysicalMemory``
        instance.  This is not a display override: bytes and typed objects are
        restored at the authoritative memory surface.
        """
        self._spans = list(snapshot.spans)
        self._objects = {item.object_id: item for item in snapshot.objects}
        self._index_cache = None
        self._object_index_cache = None
        self._address_cache.clear()
        self._revision += 1
        self._object_revisions = {item.object_id: self._revision for item in snapshot.objects}

    def _overlapping_objects(self, start: MemoryAddress, end: MemoryAddress) -> tuple[MemoryObject, ...]:
        if self._object_index_cache is None:
            grouped: dict[str, list[MemoryObject]] = {}
            for item in self._objects.values():
                grouped.setdefault(item.start.space, []).append(item)
            for items in grouped.values():
                items.sort(key=lambda item: item.start.offset)
            built: dict[str, tuple[tuple[int, ...], tuple[int, ...], tuple[MemoryObject, ...]]] = {}
            for space, items in grouped.items():
                maximum = -1
                prefix: list[int] = []
                for item in items:
                    maximum = max(maximum, item.end.offset)
                    prefix.append(maximum)
                built[space] = (tuple(item.start.offset for item in items), tuple(prefix), tuple(items))
            self._object_index_cache = built
        offsets, prefix_ends, objects = self._object_index_cache.get(start.space, ((), (), ()))
        if not objects:
            return ()
        position = bisect_right(offsets, start.offset)
        # prefix_ends is monotonic; every object before ``left`` ends at or
        # before start, even when a large view encloses several small views.
        left = bisect_right(prefix_ends, start.offset, 0, position)
        result: list[MemoryObject] = []
        for item in objects[left:]:
            if item.start.offset >= end.offset:
                break
            if item.end.offset > start.offset:
                result.append(item)
        return tuple(result)


def _read_from_spans(
    spans: Iterable[MemorySpan],
    start: MemoryAddress,
    size: int,
) -> MemoryRead:
    size = max(0, int(size))
    end = start.offset + size
    relevant = sorted(
        (
            span for span in spans
            if span.start.space == start.space and span.start.offset < end and span.end.offset > start.offset
        ),
        key=lambda item: item.start.offset,
    )
    result: list[MemorySpan] = []
    cursor = start.offset
    for span in relevant:
        if span.start.offset > cursor:
            gap = min(span.start.offset, end) - cursor
            result.append(MemorySpan(
                MemoryAddress(start.root, cursor, start.expression),
                gap,
                None,
                "",
                "unknown",
                MemoryProvenance(ProvenanceKind.UNKNOWN),
            ))
            cursor += gap
        if cursor >= end:
            break
        left = max(cursor, span.start.offset)
        right = min(end, span.end.offset)
        if right > left:
            result.append(span.slice(left - span.start.offset, right - span.start.offset))
            cursor = right
    if cursor < end:
        result.append(MemorySpan(
            MemoryAddress(start.root, cursor, start.expression),
            end - cursor,
            None,
            "",
            "unknown",
            MemoryProvenance(ProvenanceKind.UNKNOWN),
        ))
    return MemoryRead(start, size, tuple(item for item in result if item.length > 0))


def _read_from_index(
    index: Mapping[str, tuple[tuple[int, ...], tuple[MemorySpan, ...]]],
    start: MemoryAddress,
    size: int,
) -> MemoryRead:
    offsets, spans = index.get(start.space, ((), ()))
    if not spans:
        return _read_from_spans((), start, size)
    position = max(0, bisect_right(offsets, start.offset) - 1)
    end = start.offset + max(0, int(size))
    candidates: list[MemorySpan] = []
    for span in spans[position:]:
        if span.start.offset >= end:
            break
        if span.end.offset > start.offset:
            candidates.append(span)
    return _read_from_spans(candidates, start, size)


def _merge_spans(spans: list[MemorySpan]) -> list[MemorySpan]:
    result: list[MemorySpan] = []
    for span in spans:
        if span.length <= 0:
            continue
        if not result:
            result.append(span)
            continue
        previous = result[-1]
        mergeable = (
            previous.end.offset == span.start.offset
            and previous.start.space == span.start.space
            and previous.symbolic == span.symbolic == ""
            and previous.data is not None
            and span.data is not None
            and previous.state == span.state
            and previous.provenance == span.provenance
        )
        if mergeable:
            result[-1] = replace(previous, length=previous.length + span.length, data=(previous.data or b"") + (span.data or b""))
        else:
            result.append(span)
    return result
