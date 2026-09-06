from __future__ import annotations

from pwncraft.features.heapviz.constraints.result import ConstraintResult


def validate_top(
    address: int,
    size: int,
    *,
    alignment: int,
    minsize: int,
    system_mem: int | None,
    mapping_start: int | None = None,
    mapping_end: int | None = None,
) -> ConstraintResult:
    if address < 0 or address % alignment:
        return ConstraintResult.invalid("invalid_top_address", "Top 地址必须有效且满足对齐。", "top_address")
    chunksize = size & ~0x7
    if chunksize < minsize or chunksize % alignment:
        return ConstraintResult.invalid("invalid_top_size", "Top size 不满足 MINSIZE/对齐规则。", "top_size")
    if system_mem is not None and chunksize > system_mem:
        return ConstraintResult.corruption("top_exceeds_system_mem", "Top size 超过 system_mem，当前 metadata 已损坏。", "top_size")
    if mapping_start is not None and mapping_end is not None and not (mapping_start <= address < address + chunksize <= mapping_end):
        return ConstraintResult.invalid("top_outside_mapping", "Top 范围超出 heap mapping。", "top_address")
    return ConstraintResult.valid(top_address=address, top_size=chunksize)
