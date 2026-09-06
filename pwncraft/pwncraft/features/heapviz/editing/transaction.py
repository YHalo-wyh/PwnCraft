"""EditTransaction — the only path from canvas edits into heap truth
(v0.20 Phase D, §74–§77).

Lifecycle: ``begin`` → ``preview`` (pure draft; never touches the model) →
``validate`` → ``commit`` / ``cancel``.  Semantic patches and layout
changes keep separate undo stacks: undoing a byte write never moves a
card, and vice-versa.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..grid.physical_grid import intersect_coverage


@dataclass
class SemanticPatch:
    """One committed semantic byte-range change."""

    subject_id: str
    direction: str          # "n" (underflow) | "s" (overflow)
    start: int              # absolute chunk-offset range
    end: int
    payload: bytes | None   # None = coverage extent without byte payload
    summary: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "direction": self.direction,
            "start": self.start,
            "end": self.end,
            "payload": self.payload.hex() if self.payload else None,
            "summary": self.summary,
        }


@dataclass
class EditTransaction:
    subject_id: str = ""
    direction: str = "s"
    start: int = 0
    end: int = 0
    payload: bytes | None = None
    committed: bool = False
    cancelled: bool = False
    errors: tuple[str, ...] = field(default_factory=tuple)
    validator: Callable[["EditTransaction"], tuple[str, ...]] | None = None

    # ------------------------------------------------------------------
    @property
    def is_draft(self) -> bool:
        return not (self.committed or self.cancelled)

    def preview(self, end: int, payload: bytes | None = None) -> None:
        """Drag update.  Pure draft state; nothing observable may read it."""
        self.end = max(self.start, int(end))
        self.payload = payload

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if self.end <= self.start:
            errors.append("覆盖范围为空")
        if self.payload is not None and len(self.payload) > self.end - self.start:
            errors.append("payload 超出覆盖范围")
        if self.validator is not None:
            errors.extend(self.validator(self))
        self.errors = tuple(errors)
        return self.errors

    def commit(self) -> SemanticPatch | None:
        if self.validate():
            return None
        self.committed = True
        return SemanticPatch(
            self.subject_id,
            self.direction,
            self.start,
            self.end,
            self.payload,
            f"{self.subject_id} {self.direction} {self.start:#x}..{self.end:#x}",
        )

    def cancel(self) -> None:
        self.cancelled = True


class TransactionStack:
    """Semantic undo/redo.  Layout (visual) edits use their own stack."""

    def __init__(self, apply_patch: Callable[[SemanticPatch], object] | None = None):
        self._undo: list[SemanticPatch] = []
        self._redo: list[SemanticPatch] = []
        self._apply_patch = apply_patch

    @property
    def undo_depth(self) -> int:
        return len(self._undo)

    @property
    def redo_depth(self) -> int:
        return len(self._redo)

    def commit(self, transaction: EditTransaction) -> SemanticPatch | None:
        patch = transaction.commit()
        if patch is None:
            return None
        self._undo.append(patch)
        self._redo.clear()
        if self._apply_patch is not None:
            self._apply_patch(patch)
        return patch

    def undo(self) -> SemanticPatch | None:
        return self._undo.pop() if self._undo else None

    def redo(self) -> SemanticPatch | None:
        patch = self._redo.pop() if self._redo else None
        return patch

    def push_redo(self, patch: SemanticPatch) -> None:
        self._redo.append(patch)


def coverage_rows(patch: SemanticPatch, rows) -> tuple:
    """Convenience: which visual rows a committed patch touches."""
    return intersect_coverage(rows, patch.start, patch.end)
