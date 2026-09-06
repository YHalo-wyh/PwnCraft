from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class PayloadSegment:
    offset: int
    length: int
    raw_bytes: bytes | None = None
    symbolic_value: str = ""
    expression: str = ""
    endian: str = "little"
    source_location: str = ""
    confidence: str = "derived"  # observed | derived | inferred | assumed | unknown

    @property
    def end(self) -> int:
        return self.offset + self.length

    @property
    def known(self) -> bool:
        return self.raw_bytes is not None

    def shifted(self, delta: int) -> PayloadSegment:
        return replace(self, offset=self.offset + int(delta))

    def slice(self, begin: int, end: int) -> PayloadSegment:
        begin = max(self.offset, begin)
        end = min(self.end, end)
        local_start = begin - self.offset
        local_end = end - self.offset
        data = self.raw_bytes[local_start:local_end] if self.raw_bytes is not None else None
        return replace(self, offset=begin, length=max(0, end - begin), raw_bytes=data)

    def display(self) -> str:
        if self.raw_bytes is not None:
            return repr(self.raw_bytes)
        return self.symbolic_value or self.expression or "unknown"


@dataclass(frozen=True)
class PayloadIR:
    expression: str
    segments: tuple[PayloadSegment, ...] = ()
    length: int | None = 0
    confidence: str = "derived"
    diagnostics: tuple[str, ...] = ()

    @classmethod
    def unknown(cls, expression: str, diagnostic: str = "payload length is unknown") -> PayloadIR:
        return cls(expression, (), None, "unknown", (diagnostic,))

    @classmethod
    def from_bytes(cls, data: bytes, expression: str = "") -> PayloadIR:
        segment = PayloadSegment(0, len(data), data, "", expression or repr(data)) if data else None
        return cls(expression or repr(data), (segment,) if segment else (), len(data), "derived")

    @classmethod
    def symbolic(cls, expression: str, length: int, *, endian: str = "little") -> PayloadIR:
        return cls(
            expression,
            (PayloadSegment(0, length, None, expression, expression, endian, confidence="inferred"),),
            length,
            "inferred",
        )

    def concat(self, other: PayloadIR, expression: str = "") -> PayloadIR:
        if self.length is None or other.length is None:
            return PayloadIR.unknown(expression or f"({self.expression}) + ({other.expression})")
        shifted = tuple(item.shifted(self.length) for item in other.segments)
        return PayloadIR(
            expression or f"({self.expression}) + ({other.expression})",
            _coalesce_segments(_overlay_segments((*self.segments, *shifted))),
            self.length + other.length,
            _weakest(self.confidence, other.confidence),
            (*self.diagnostics, *other.diagnostics),
        )

    def repeat(self, count: int, expression: str = "") -> PayloadIR:
        if count < 0 or count > 0x100000 or self.length is None:
            return PayloadIR.unknown(expression or self.expression, "payload repeat is not statically bounded")
        materialized = self.materialize()
        if materialized is not None:
            return PayloadIR.from_bytes(materialized * count, expression or f"({self.expression}) * {count}")
        segments = tuple(
            item.shifted(index * self.length)
            for index in range(count)
            for item in self.segments
        )
        return PayloadIR(expression or f"({self.expression}) * {count}", _coalesce_segments(segments), self.length * count, self.confidence, self.diagnostics)

    def placed(self, offset: int, expression: str = "") -> PayloadIR:
        if self.length is None:
            return self
        return PayloadIR(expression or self.expression, tuple(item.shifted(offset) for item in self.segments), offset + self.length, self.confidence, self.diagnostics)

    def overlay(self, other: PayloadIR, *, offset: int = 0, expression: str = "") -> PayloadIR:
        if other.length is None:
            return PayloadIR.unknown(expression or self.expression, "sparse payload member length is unknown")
        total = max(self.length or 0, offset + other.length)
        incoming = tuple(item.shifted(offset) for item in other.segments)
        return PayloadIR(
            expression or self.expression,
            _coalesce_segments(_overlay_segments((*self.segments, *incoming))),
            total,
            _weakest(self.confidence, other.confidence),
            (*self.diagnostics, *other.diagnostics),
        )

    def slice(self, begin: int, end: int, expression: str = "") -> PayloadIR:
        if self.length is None:
            return PayloadIR.unknown(expression or self.expression)
        begin = max(0, begin)
        end = max(begin, min(end, self.length))
        segments = tuple(
            item.slice(begin, end).shifted(-begin)
            for item in self.segments
            if item.offset < end and item.end > begin
        )
        return PayloadIR(expression or self.expression, segments, end - begin, self.confidence, self.diagnostics)

    def materialize(self, fill: bytes | None = None) -> bytes | None:
        if self.length is None:
            return None
        output = bytearray(fill * self.length if fill and len(fill) == 1 else b"\x00" * self.length)
        covered = bytearray(self.length)
        for segment in self.segments:
            if segment.raw_bytes is None or len(segment.raw_bytes) != segment.length:
                return None
            output[segment.offset:segment.end] = segment.raw_bytes
            covered[segment.offset:segment.end] = b"\x01" * segment.length
        if not all(covered) and fill is None:
            return None
        return bytes(output)

    def segment_at(self, offset: int) -> PayloadSegment | None:
        return next((item for item in reversed(self.segments) if item.offset <= offset < item.end), None)

    def fill_gaps(
        self,
        *,
        raw_fill: bytes | None = None,
        symbolic_fill: str = "flat default cyclic filler",
        target_length: int | None = None,
    ) -> PayloadIR:
        """Make every transmitted byte explicit without inventing its value.

        Pwntools ``flat``/``fit`` transmits filler in sparse gaps.  When the
        filler is not explicitly provided we preserve the range as an inferred
        symbolic segment instead of silently leaving it unwritten or claiming
        zero bytes.
        """
        if self.length is None:
            return self
        total = max(self.length, int(target_length or 0))
        result = list(self.segments)
        cursor = 0
        for segment in sorted(self.segments, key=lambda item: item.offset):
            if segment.offset > cursor:
                length = segment.offset - cursor
                data = raw_fill * length if raw_fill and len(raw_fill) == 1 else None
                result.append(PayloadSegment(
                    cursor, length, data, "" if data is not None else symbolic_fill,
                    repr(data) if data is not None else symbolic_fill,
                    confidence="derived" if data is not None else "inferred",
                ))
            cursor = max(cursor, segment.end)
        if cursor < total:
            length = total - cursor
            data = raw_fill * length if raw_fill and len(raw_fill) == 1 else None
            result.append(PayloadSegment(
                cursor, length, data, "" if data is not None else symbolic_fill,
                repr(data) if data is not None else symbolic_fill,
                confidence="derived" if data is not None else "inferred",
            ))
        confidence = self.confidence if raw_fill is not None else _weakest(self.confidence, "inferred")
        return replace(self, segments=_coalesce_segments(_overlay_segments(tuple(result))), length=total, confidence=confidence)


def _overlay_segments(segments: tuple[PayloadSegment, ...]) -> tuple[PayloadSegment, ...]:
    """Return non-overlapping segments where later entries win."""
    result: list[PayloadSegment] = []
    for incoming in segments:
        if incoming.length <= 0:
            continue
        kept: list[PayloadSegment] = []
        for current in result:
            if current.end <= incoming.offset or current.offset >= incoming.end:
                kept.append(current)
                continue
            if current.offset < incoming.offset:
                kept.append(current.slice(current.offset, incoming.offset))
            if current.end > incoming.end:
                kept.append(current.slice(incoming.end, current.end))
        kept.append(incoming)
        result = sorted(kept, key=lambda item: item.offset)
    return tuple(result)


def _coalesce_segments(segments: tuple[PayloadSegment, ...]) -> tuple[PayloadSegment, ...]:
    # Construction boundaries are semantic evidence: two adjacent p64 words
    # are distinct PayloadIR segments even when their outer ``flat`` source
    # expression is identical.  Byte spans may be coalesced later by the
    # physical-memory store, but the payload layout must retain exact offsets.
    return tuple(segment for segment in segments if segment.length > 0)


def _weakest(left: str, right: str) -> str:
    order = {"observed": 5, "calibrated": 4, "derived": 3, "inferred": 2, "assumed": 1, "unknown": 0}
    return left if order.get(left, 0) <= order.get(right, 0) else right
