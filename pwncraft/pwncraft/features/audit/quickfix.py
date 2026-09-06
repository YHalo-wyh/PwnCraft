"""Quick Fix applier (VNext.3.1 #3).

stdlib text patch: replaces the diagnostic's `fix_target` text on the
reported line. LibCST remains an optional accelerator for structural edits —
the core applier must work with zero dependencies (Offline-First).

The applier NEVER runs automatically: the user (or editor UI) calls it
explicitly for one diagnostic at a time.
"""
from __future__ import annotations

from pwncraft.features.audit.model import Diagnostic, SourceSpan


def apply_quick_fix(source: str, diagnostic: dict) -> tuple[str, str]:
    """Apply one diagnostic's suggested_fix to `source`.

    Returns (new_source, status):
      "applied"        text replaced (fix_target found on the reported line)
      "already-fixed"  fix_target no longer present on that line (stale diag)
      "no-fix"         diagnostic carries no suggested_fix/fix_target
      "ambiguous"      fix_target occurs multiple times on the line
    """
    fix = str(diagnostic.get("suggested_fix") or "")
    target = str(diagnostic.get("fix_target") or "")
    line_no = int(diagnostic.get("line") or 0)
    if not fix or not target:
        return source, "no-fix"
    lines = source.split("\n")
    if not (1 <= line_no <= len(lines)):
        return source, "no-fix"
    line = lines[line_no - 1]
    occurrences = line.count(target)
    if occurrences == 0:
        return source, "already-fixed"
    if occurrences > 1:
        return source, "ambiguous"
    lines[line_no - 1] = line.replace(target, fix, 1)
    return "\n".join(lines), "applied"
