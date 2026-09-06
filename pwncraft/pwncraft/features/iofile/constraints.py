from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .snapshot import FileSnapshot


class FileValidationStatus(str, Enum):
    VALID = "VALID"
    REPRESENTABLE_CORRUPTION = "REPRESENTABLE_CORRUPTION"
    INVALID = "INVALID"


@dataclass(frozen=True)
class FileValidation:
    status: FileValidationStatus
    issues: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.status is not FileValidationStatus.INVALID


class FileConstraintEngine:
    def __init__(self, mapped_ranges: tuple[tuple[int, int], ...] = ()):
        self.mapped_ranges = mapped_ranges

    def validate_edit(self, snapshot: FileSnapshot, name: str, value: int, *, observed: bool = False) -> FileValidation:
        try:
            field = snapshot.layout.field(name)
        except StopIteration:
            return FileValidation(FileValidationStatus.INVALID, (f"未知字段：{name}",))
        if not 0 <= value < (1 << (field.width * 8)):
            return FileValidation(FileValidationStatus.INVALID, (f"{name} 无法装入 {field.width} 字节",))
        if field.kind == "structural_pointer" and value:
            if value % field.width:
                return FileValidation(FileValidationStatus.INVALID, (f"{name} 必须按 {field.width} 字节对齐",))
            if self.mapped_ranges and not any(start <= value < end for start, end in self.mapped_ranges):
                if observed:
                    return FileValidation(FileValidationStatus.REPRESENTABLE_CORRUPTION, (f"{name} 指向未映射地址（runtime observed）",))
                return FileValidation(FileValidationStatus.INVALID, (f"{name} 必须指向当前已知映射；直接编辑不能凭空制造映射",))
        candidate = snapshot.edit(name, value)
        ordering = self.validate_snapshot(candidate)
        if ordering.status is FileValidationStatus.REPRESENTABLE_CORRUPTION and not observed:
            return FileValidation(FileValidationStatus.INVALID, ordering.issues)
        return ordering

    def validate_snapshot(self, snapshot: FileSnapshot) -> FileValidation:
        issues = []
        for prefix in ("_IO_read", "_IO_write"):
            values = [snapshot.fields.get(prefix + suffix) for suffix in ("_base", "_ptr", "_end")]
            numbers = [item.value if item else None for item in values]
            if all(value is not None for value in numbers) and not numbers[0] <= numbers[1] <= numbers[2]:
                issues.append(f"{prefix}_base <= ptr <= end 不成立")
        mode = snapshot.fields.get("_mode")
        if mode and mode.value is not None and mode.value > 0x7FFFFFFF:
            issues.append("_mode 超出 signed int 正常范围")
        return FileValidation(
            FileValidationStatus.REPRESENTABLE_CORRUPTION if issues else FileValidationStatus.VALID,
            tuple(issues),
        )
