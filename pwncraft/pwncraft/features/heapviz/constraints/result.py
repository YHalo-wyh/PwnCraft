from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ValidationStatus(Enum):
    VALID = "valid"
    REPRESENTABLE_CORRUPTION = "representable_corruption"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ConstraintIssue:
    code: str
    message: str
    field: str = ""
    severity: str = "error"


@dataclass(frozen=True)
class ConstraintResult:
    status: ValidationStatus
    issues: tuple[ConstraintIssue, ...] = ()
    normalized: dict[str, object] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.status in {ValidationStatus.VALID, ValidationStatus.REPRESENTABLE_CORRUPTION}

    @property
    def corrupted(self) -> bool:
        return self.status is ValidationStatus.REPRESENTABLE_CORRUPTION

    @classmethod
    def valid(cls, **normalized: object) -> ConstraintResult:
        return cls(ValidationStatus.VALID, (), normalized)

    @classmethod
    def invalid(cls, code: str, message: str, field: str = "") -> ConstraintResult:
        return cls(ValidationStatus.INVALID, (ConstraintIssue(code, message, field),))

    @classmethod
    def corruption(cls, code: str, message: str, field: str = "", **normalized: object) -> ConstraintResult:
        return cls(
            ValidationStatus.REPRESENTABLE_CORRUPTION,
            (ConstraintIssue(code, message, field, "warning"),),
            normalized,
        )

    @classmethod
    def unknown(cls, code: str, message: str, field: str = "") -> ConstraintResult:
        return cls(ValidationStatus.UNKNOWN, (ConstraintIssue(code, message, field, "info"),))
