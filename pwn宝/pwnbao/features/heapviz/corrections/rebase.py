from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RebaseResult:
    status: str
    old_fingerprint: str = ""
    new_fingerprint: str = ""
    message: str = ""


def rebase_fingerprint(old: str, new: str) -> RebaseResult:
    if old == new:
        return RebaseResult("matched", old, new, "fingerprint unchanged")
    return RebaseResult("stale", old, new, "source structure changed; confirmation required")
