from __future__ import annotations

from dataclasses import replace

from .model import CorrectionPatch, PatchStatus


class CorrectionHistory:
    def __init__(self) -> None:
        self._done: list[CorrectionPatch] = []
        self._undone: list[CorrectionPatch] = []

    @property
    def done(self) -> tuple[CorrectionPatch, ...]:
        return tuple(self._done)

    def push(self, patch: CorrectionPatch) -> None:
        self._done.append(patch)
        self._undone.clear()

    def undo(self) -> CorrectionPatch | None:
        if not self._done:
            return None
        patch = self._done.pop()
        undone = replace(patch, status=PatchStatus.UNDONE)
        self._undone.append(patch)
        return undone

    def redo(self) -> CorrectionPatch | None:
        if not self._undone:
            return None
        patch = replace(self._undone.pop(), status=PatchStatus.ACTIVE)
        self._done.append(patch)
        return patch


CorrectionCommand = CorrectionPatch
LayoutCommand = CorrectionPatch
