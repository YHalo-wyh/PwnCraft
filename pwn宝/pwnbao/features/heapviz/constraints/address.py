from __future__ import annotations

from pwnbao.features.heapviz.constraints.result import ConstraintResult
from pwnbao.features.heapviz.memory import MemoryAddress, PhysicalMemory, PhysicalMemorySnapshot


def validate_memory_range(
    memory: PhysicalMemory | PhysicalMemorySnapshot,
    address: MemoryAddress | str | int,
    length: int,
    *,
    allow_unmapped: bool = False,
) -> ConstraintResult:
    if length <= 0:
        return ConstraintResult.invalid("invalid_length", "写入长度必须大于 0。", "length")
    try:
        start = MemoryAddress.parse(address)
    except (TypeError, ValueError) as error:
        return ConstraintResult.invalid("address_parse", f"地址无法解析：{error}", "address")
    if start.offset < 0:
        return ConstraintResult.invalid("negative_address", "地址空间偏移不能为负数。", "address")
    end = start.add(length)
    if end.offset < start.offset:
        return ConstraintResult.invalid("range_overflow", "地址范围溢出。", "address")
    objects = memory.overlaps(start, end)
    covered = any(item.start.offset <= start.offset and item.end.offset >= end.offset for item in objects)
    if not covered and not allow_unmapped:
        return ConstraintResult.invalid("unmapped_range", "当前模式不允许写入未登记的物理内存范围。", "address")
    return ConstraintResult.valid(address=start, end=end, objects=objects)
