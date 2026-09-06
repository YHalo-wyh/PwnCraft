"""Physical grid: cells derived from real chunk layout (v0.20 Phase D)."""
from .physical_grid import (
    HEADER_FIELDS,
    PhysicalCell,
    PhysicalRow,
    build_chunk_rows,
    covered_fraction,
    intersect_coverage,
    rows_touching,
    virtualize,
)

__all__ = [
    "HEADER_FIELDS",
    "PhysicalCell",
    "PhysicalRow",
    "build_chunk_rows",
    "covered_fraction",
    "intersect_coverage",
    "rows_touching",
    "virtualize",
]
