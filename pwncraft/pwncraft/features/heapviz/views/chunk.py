from __future__ import annotations

from dataclasses import dataclass

from pwncraft.features.heapviz.memory import MemoryAddress, PhysicalMemorySnapshot


@dataclass(frozen=True)
class TypedFieldValue:
    offset: int
    size: int
    name: str
    role: str
    value: str
    address: str
    state: str
    provenance: str
    meaning: str = ""
    stored_value: str = ""
    decoded_value: str = ""


class TypedMemoryView:
    view_kind = "memory"

    def fields(self) -> tuple[TypedFieldValue, ...]:
        raise NotImplementedError


class TopChunkView(TypedMemoryView):
    view_kind = "top_chunk"

    def __init__(self, memory: PhysicalMemorySnapshot, address: MemoryAddress | str | int, *, bits: int = 64):
        self.memory = memory
        self.address = MemoryAddress.parse(address)
        self.word = 8 if bits == 64 else 4

    def raw_size(self) -> int | None:
        return self.memory.read_uint(self.address.add(self.word), self.word)

    def chunk_size(self) -> int | None:
        value = self.raw_size()
        return value & ~0x7 if value is not None else None

    def fields(self) -> tuple[TypedFieldValue, ...]:
        result: list[TypedFieldValue] = []
        for offset, name, meaning in (
            (0, "prev_size", "previous physical chunk size"),
            (self.word, "size", "top size plus allocator flags"),
        ):
            address = self.address.add(offset)
            read = self.memory.read(address, self.word)
            raw = read.data
            value = hex(int.from_bytes(raw, "little")) if raw is not None else (read.symbolic or "unknown")
            provenance = next((item.kind.value for item in read.provenance if item.kind.value != "unknown"), "unknown")
            result.append(TypedFieldValue(
                offset, self.word, name, name, value, str(address),
                "metadata" if value != "unknown" else "unknown", provenance, meaning,
            ))
        size = self.chunk_size()
        end = str(self.address.add(size)) if size is not None else "unknown"
        result.append(TypedFieldValue(
            self.word * 2, 0, "end", "end", end, end, "metadata" if size is not None else "unknown",
            "derived", "top address + chunksize(top)",
        ))
        return tuple(result)


class ChunkMemoryView(TypedMemoryView):
    """Typed malloc_chunk view backed exclusively by a memory snapshot."""

    def __init__(
        self,
        memory: PhysicalMemorySnapshot,
        address: MemoryAddress | str | int,
        *,
        bits: int = 64,
        lifecycle: str = "allocated",
        bin_location: str = "",
        chunk_size_hint: int | None = None,
        safe_linking: bool = False,
    ):
        self.memory = memory
        self.address = MemoryAddress.parse(address)
        self.word = 8 if bits == 64 else 4
        self.lifecycle = lifecycle
        self.bin_location = bin_location
        self.chunk_size_hint = chunk_size_hint
        self.safe_linking = safe_linking
        self.view_kind = self._view_kind()

    def _view_kind(self) -> str:
        location = self.bin_location.lower()
        if location.startswith("tcache"):
            return "tcache_entry"
        if location.startswith("fastbin"):
            return "fastbin_chunk"
        if "largebin" in location:
            return "largebin_chunk"
        if location == "unsorted" or "smallbin" in location:
            return "doubly_linked_chunk"
        if self.lifecycle == "fake":
            return "fake_chunk"
        return "allocated_chunk"

    def chunk_size(self) -> int | None:
        raw = self.memory.read_uint(self.address.add(self.word), self.word)
        return (raw & ~0x7) if raw is not None else self.chunk_size_hint

    def fields(self) -> tuple[TypedFieldValue, ...]:
        specs: list[tuple[int, str, str, str]] = [
            (0, "prev_size", "prev_size", "previous physical chunk size when PREV_INUSE is clear"),
            (self.word, "size", "size", "aligned chunk size plus allocator flags"),
        ]
        if self.view_kind == "tcache_entry":
            specs.extend([
                (self.word * 2, "next", "fd", "safe-linked tcache next pointer"),
                (self.word * 3, "key", "key", "tcache double-free key"),
            ])
        elif self.view_kind == "fastbin_chunk":
            specs.append((self.word * 2, "fd", "fd", "safe-linked fastbin forward pointer"))
        elif self.view_kind == "doubly_linked_chunk":
            specs.extend([
                (self.word * 2, "fd", "fd", "forward bin link"),
                (self.word * 3, "bk", "bk", "backward bin link"),
            ])
        elif self.view_kind == "largebin_chunk":
            specs.extend([
                (self.word * 2, "fd", "fd", "forward bin link"),
                (self.word * 3, "bk", "bk", "backward bin link"),
                (self.word * 4, "fd_nextsize", "fd_nextsize", "next larger-size peer"),
                (self.word * 5, "bk_nextsize", "bk_nextsize", "previous larger-size peer"),
            ])
        else:
            specs.extend([
                (self.word * 2, "user[0]", "user", "allocated user data"),
                (self.word * 3, f"user[{self.word}]", "user", "allocated user data"),
            ])
        return tuple(self._field(offset, name, role, meaning) for offset, name, role, meaning in specs)

    def _field(self, offset: int, name: str, role: str, meaning: str) -> TypedFieldValue:
        address = self.address.add(offset)
        read = self.memory.read(address, self.word)
        raw = read.data
        if raw is not None:
            integer = int.from_bytes(raw, "little")
            value = repr(raw) if role == "user" else hex(integer)
            state = "zero" if not any(raw) else ("metadata" if role != "user" else "known")
        elif read.symbolic:
            value = read.symbolic
            state = "metadata" if role != "user" else "known"
        elif role == "user":
            known = b"".join(span.data or b"" for span in read.spans if span.data is not None)
            symbolic_parts = [span.symbolic for span in read.spans if span.symbolic]
            if known:
                value = repr(known)
                state = "zero" if not any(known) else "known"
            elif symbolic_parts:
                value = " + ".join(symbolic_parts)
                state = "known"
            else:
                value = "unknown"
                state = "unknown"
        else:
            value = "unknown"
            state = "unknown"
        provenance = "unknown"
        for item in read.provenance:
            if item.kind.value != "unknown":
                provenance = item.kind.value
                break
        stored = value if role == "fd" and self.safe_linking else ""
        decoded = ""
        if stored and raw is not None and address.concrete:
            decoded = hex(int.from_bytes(raw, "little") ^ (address.offset >> 12))
        elif stored and read.symbolic:
            decoded = f"DECODE_PTR({address}, {read.symbolic})"
        return TypedFieldValue(
            offset, self.word, name, role, value, str(address), state, provenance, meaning,
            stored_value=stored, decoded_value=decoded,
        )

    def field_at(self, absolute: MemoryAddress | str | int) -> TypedFieldValue | None:
        address = MemoryAddress.parse(absolute)
        delta = self.address.distance_to(address)
        if delta is None:
            return None
        for field in self.fields():
            if field.offset <= delta < field.offset + field.size:
                return field
        size = self.chunk_size()
        if size is not None and self.word * 2 <= delta < size:
            aligned = delta - (delta % self.word)
            return self._field(aligned, f"user[0x{aligned - self.word * 2:x}]", "user", "allocated user data")
        return None
