from __future__ import annotations

from dataclasses import dataclass

from pwncraft.features.heapviz.constraints.address import validate_memory_range
from pwncraft.features.heapviz.constraints.bins import validate_doubly_linked_node
from pwncraft.features.heapviz.constraints.chunk import validate_chunk_size, validate_prev_size
from pwncraft.features.heapviz.constraints.freelist import pointer_aligned, protect_ptr, reveal_ptr
from pwncraft.features.heapviz.constraints.result import ConstraintResult, ValidationStatus
from pwncraft.features.heapviz.constraints.top import validate_top
from pwncraft.features.heapviz.memory import PhysicalMemory, PhysicalMemorySnapshot
from pwncraft.features.heapviz.models import AllocatorConfig


@dataclass(frozen=True)
class EditRequest:
    field: str
    address: str | int
    value: int | bytes | str
    width: int
    object_id: str = ""
    decoded_pointer: bool = False


class ConstraintEngine:
    def __init__(self, config: AllocatorConfig | None = None) -> None:
        self.config = config or AllocatorConfig()
        self.pointer_width = max(1, self.config.bits // 8)
        self.minsize = 4 * self.pointer_width

    def validate(
        self,
        request: EditRequest,
        memory: PhysicalMemory | PhysicalMemorySnapshot,
        *,
        allow_unmapped: bool = False,
    ) -> ConstraintResult:
        if request.field == "bin_location":
            return ConstraintResult.invalid(
                "derived_field",
                "bin_location 是 allocator 派生只读字段，必须修正真实 freelist/head/memory。",
                request.field,
            )
        if request.width <= 0:
            return ConstraintResult.invalid("invalid_width", "字段宽度必须大于 0。", request.field)
        range_result = validate_memory_range(memory, request.address, request.width, allow_unmapped=allow_unmapped)
        if not range_result.accepted:
            return range_result
        if isinstance(request.value, int) and not 0 <= request.value < (1 << (request.width * 8)):
            return ConstraintResult.invalid("field_width_overflow", "输入值无法装入字段宽度。", request.field)
        if isinstance(request.value, bytes) and len(request.value) != request.width:
            return ConstraintResult.invalid("byte_width_mismatch", "字节长度与字段宽度不一致。", request.field)
        if request.field in {"size", "raw_size", "chunk_size"}:
            if not isinstance(request.value, int):
                return ConstraintResult.unknown("symbolic_size", "符号 size 暂无法执行结构校验。", request.field)
            return validate_chunk_size(
                request.value,
                alignment=self.config.alignment,
                minsize=self.minsize,
                pointer_bits=self.config.bits,
            )
        if request.field == "prev_size":
            if not isinstance(request.value, int):
                return ConstraintResult.unknown("symbolic_prev_size", "符号 prev_size 暂无法执行边界校验。", request.field)
            objects = tuple(memory.objects)
            current = next((item for item in objects if item.object_id == request.object_id), None)
            if current is None:
                return ConstraintResult.invalid("unknown_chunk_view", "当前 Physical Chunk view 不存在。", request.field)
            previous = next(
                (
                    item for item in objects
                    if item.start.space == current.start.space and item.end.offset == current.start.offset
                ),
                None,
            )
            return self.validate_prev_size(
                current.start.offset,
                request.value,
                previous_address=previous.start.offset if previous else None,
                previous_size=previous.size if previous else None,
                observed=True,
            )
        if request.field in {"fd", "next"} and isinstance(request.value, int):
            normalized = request.value
            if request.decoded_pointer and self.config.safe_linking:
                address = range_result.normalized["address"]
                if not address.concrete:
                    return ConstraintResult.unknown("symbolic_field_address", "Safe-Linking 需要具体字段地址。", request.field)
                normalized = protect_ptr(address.offset, request.value)
            if request.decoded_pointer and not pointer_aligned(request.value, self.config.alignment):
                return ConstraintResult.corruption(
                    "unaligned_freelist_pointer",
                    "freelist 指针字节可表示，但 decoded target 不满足对齐。",
                    request.field,
                    stored=normalized,
                )
            return ConstraintResult.valid(stored=normalized)
        if request.field in {"bk", "key"} and isinstance(request.value, int):
            if request.value and not pointer_aligned(request.value, self.config.alignment):
                return ConstraintResult.corruption(
                    "unaligned_metadata_pointer",
                    f"{request.field} 字节可表示，但指针不满足 {self.config.alignment:#x} 对齐。",
                    request.field,
                )
            return ConstraintResult.valid(value=request.value)
        return ConstraintResult.valid(value=request.value)

    def validate_prev_size(self, *args: object, observed: bool = False, **kwargs: object) -> ConstraintResult:
        result = validate_prev_size(*args, alignment=self.config.alignment, **kwargs)  # type: ignore[arg-type]
        if result.status is ValidationStatus.REPRESENTABLE_CORRUPTION and not observed:
            issue = result.issues[0]
            return ConstraintResult.invalid(issue.code, issue.message, issue.field)
        return result

    def validate_bin_links(self, victim: int, fd_bk: int | None, bk_fd: int | None) -> ConstraintResult:
        return validate_doubly_linked_node(victim, fd_bk, bk_fd)

    def validate_top(self, address: int, size: int, **kwargs: object) -> ConstraintResult:
        return validate_top(address, size, alignment=self.config.alignment, minsize=self.minsize, **kwargs)  # type: ignore[arg-type]

    @staticmethod
    def encode_safe_link(field_address: int, pointer: int) -> int:
        return protect_ptr(field_address, pointer)

    @staticmethod
    def decode_safe_link(field_address: int, stored: int) -> int:
        return reveal_ptr(field_address, stored)
