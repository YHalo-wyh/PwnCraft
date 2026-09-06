from __future__ import annotations

from pwnbao.features.heapviz.constraints.result import ConstraintResult


def encode_chunk_size(chunksize: int, *, prev_inuse: bool = True, is_mmapped: bool = False, non_main_arena: bool = False) -> int:
    """Encode a structured (chunksize, flags) edit back into the raw size word.

    This is the inverse of the decoder used by ``validate_chunk_size``: the
    field editor shows Chunk Size + PREV_INUSE/IS_MMAPPED/NON_MAIN_ARENA flags
    and must sync back to the 8-byte raw size before writing PhysicalMemory.
    """
    flags = 0
    if prev_inuse:
        flags |= 0x1
    if is_mmapped:
        flags |= 0x2
    if non_main_arena:
        flags |= 0x4
    return (int(chunksize) & ~0x7) | flags


def validate_chunk_size(size: int, *, alignment: int, minsize: int, pointer_bits: int = 64) -> ConstraintResult:
    if size < 0:
        return ConstraintResult.invalid("negative_size", "Chunk size 不能为负数。", "size")
    if size >= 1 << pointer_bits:
        return ConstraintResult.invalid("size_overflow", "Chunk size 超出指针宽度。", "size")
    chunksize = size & ~0x7
    if chunksize < minsize:
        return ConstraintResult.invalid("below_minsize", f"chunksize 必须 >= MINSIZE ({minsize:#x})。", "size")
    if chunksize % alignment:
        return ConstraintResult.invalid("misaligned_size", f"chunksize 必须按 {alignment:#x} 对齐。", "size")
    return ConstraintResult.valid(raw_size=size, chunk_size=chunksize, flags=size & 0x7)


def validate_prev_size(
    chunk_address: int,
    prev_size: int,
    *,
    previous_address: int | None,
    previous_size: int | None,
    alignment: int,
) -> ConstraintResult:
    if prev_size <= 0 or prev_size % alignment:
        return ConstraintResult.invalid("invalid_prev_size", "prev_size 必须为正且满足对齐。", "prev_size")
    expected = chunk_address - prev_size
    if previous_address is None or previous_size is None:
        return ConstraintResult.unknown("previous_chunk_unknown", "无法静态定位前一物理 chunk。", "prev_size")
    if expected != previous_address or previous_size != prev_size:
        return ConstraintResult.corruption(
            "prev_size_mismatch",
            "prev_size 字节可存在，但与前一 chunk 的真实边界不一致。",
            "prev_size",
            expected_previous=expected,
        )
    return ConstraintResult.valid(expected_previous=expected)
