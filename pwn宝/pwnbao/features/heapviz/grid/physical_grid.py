"""PhysicalGridModel (v0.20 Phase D, §31–§36/§78–§82).

A chunk's visual unit is derived from its real physical layout:

* header rows: ``prev_size`` and ``size`` (one word each);
* user rows: ``2 * word`` bytes per row, split into left/right word cells.

The key rule (§31): **a byte quantum is a cell's interior, never a new
visual row**.  Coverage (overflow writes) is answered as *intersections
against existing rows* — the renderer tints cell interiors; it must not
create rows or rectangles of its own.
"""
from __future__ import annotations

from dataclasses import dataclass, field

HEADER_FIELDS = ("prev_size", "size")


@dataclass(frozen=True)
class PhysicalCell:
    """One addressable quantum inside a visual row."""

    start: int          # absolute offset from chunk start (inclusive)
    end: int            # exclusive
    column: int         # 0-based cell index within the row
    role: str           # "prev_size" | "size" | "user"
    row_id: str

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class PhysicalRow:
    """A visual row: fixed geometry regardless of how much of it is covered."""

    row_id: str
    start: int
    end: int
    role: str
    cells: tuple[PhysicalCell, ...] = field(default_factory=tuple)

    @property
    def size(self) -> int:
        return self.end - self.start


def build_chunk_rows(
    chunk_size: int,
    word_size: int,
    *,
    chunk_id: str = "chunk",
    max_user_rows: int | None = None,
) -> tuple[PhysicalRow, ...]:
    """Derive the canonical visual rows for one chunk.

    Layout: ``prev_size`` (word), ``size`` (word), then ``2*word`` user rows.
    The final user row is clamped to the chunk end.  ``max_user_rows`` is the
    virtualizer hint: when given, only the requested number of user rows are
    materialised and the remainder is reported as ``collapsed_bytes`` by
    :func:`virtualize`.
    """
    if chunk_size <= 0 or word_size <= 0:
        return ()
    rows: list[PhysicalRow] = []
    offset = 0
    for field_name in HEADER_FIELDS:
        if offset >= chunk_size:
            break
        end = min(chunk_size, offset + word_size)
        cell = PhysicalCell(offset, end, 0, field_name, f"{chunk_id}.{field_name}")
        rows.append(PhysicalRow(cell.row_id, offset, end, field_name, (cell,)))
        offset = end
    user_index = 0
    while offset < chunk_size:
        if max_user_rows is not None and user_index >= max_user_rows:
            break
        end = min(chunk_size, offset + word_size * 2)
        cells = tuple(
            PhysicalCell(offset + column * word_size,
                         min(end, offset + (column + 1) * word_size),
                         column, "user", f"{chunk_id}.user{user_index}")
            for column in range(2)
            if offset + column * word_size < end
        )
        rows.append(PhysicalRow(f"{chunk_id}.user{user_index}", offset, end, "user", cells))
        offset = end
        user_index += 1
    return tuple(rows)


def intersect_coverage(
    rows: tuple[PhysicalRow, ...],
    cover_start: int,
    cover_end: int,
) -> tuple[tuple[PhysicalRow, int, int], ...]:
    """Intersect a coverage range with existing rows (§33).

    Returns ``(row, covered_start, covered_end)`` tuples, clipped to the row
    and merged per row.  Rows with no intersection are absent.  This is the
    ONLY computation the renderer needs: one tint per row per contiguous
    span, painted inside the row's rectangle.
    """
    spans: list[tuple[PhysicalRow, int, int]] = []
    for row in rows:
        left = max(cover_start, row.start)
        right = min(cover_end, row.end)
        if right > left:
            spans.append((row, left, right))
    return tuple(spans)


def covered_fraction(span_start: int, span_end: int, row: PhysicalRow) -> tuple[float, float]:
    """Horizontal (or vertical) mask fractions inside a row rectangle (§36)."""
    total = max(1, row.size)
    return (span_start - row.start) / total, (span_end - row.start) / total


def virtualize(
    rows: tuple[PhysicalRow, ...],
    chunk_size: int,
    *,
    keep_tail_rows: int = 1,
) -> tuple[tuple[PhysicalRow, ...], int]:
    """Collapse the untouched middle of large chunks (§37).

    Keeps everything materialised so far plus a tail of ``keep_tail_rows``
    user rows reaching the chunk end; returns ``(visible_rows,
    collapsed_bytes)``.  Coverage intersections against collapsed bytes are
    the caller's signal to re-materialise (§38).
    """
    if not rows:
        return rows, 0
    visible = list(rows)
    collapsed = 0
    last_end = rows[-1].end
    if last_end < chunk_size:
        tail_bytes = min(chunk_size - last_end, keep_tail_rows * (rows[-1].size or 1))
        visible.append(
            PhysicalRow(f"{rows[-1].row_id}.tail", last_end, last_end + tail_bytes, "user", ())
        )
        collapsed = chunk_size - (last_end + tail_bytes)
    return tuple(visible), max(0, collapsed)


def rows_touching(rows: tuple[PhysicalRow, ...], start: int, end: int) -> bool:
    """True when a coverage range reaches any materialised row (§38)."""
    return any(row.start < end and row.end > start for row in rows)
