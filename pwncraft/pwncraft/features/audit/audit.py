"""EXP Live Auditor entry (VNext.3).

audit_exp() = extract ExploitIR + run deterministic rules. Returns a list of
structured diagnostics; layer-2 (AI reasoning) consumes these plus minimal
context — never the whole EXP.
"""
from __future__ import annotations

import ast

from pwncraft.features.audit.extract import extract_exploit_ir
from pwncraft.features.audit.heap_state import run_rules
from pwncraft.features.audit.model import Diagnostic, SEVERITY_ERROR
from pwncraft.features.audit.quickfix import apply_quick_fix


def audit_exp(source: str, *, bits: int = 64, pie: bool = False,
              profile: dict | None = None) -> list[dict]:
    """Deterministic layer-1 audit. Never mutates the EXP; quick fixes are
    suggestions. Incomplete/invalid syntax yields a single EXP_PARSE
    diagnostic (editor-layer incremental parsing is a separate concern)."""
    diagnostics: list[Diagnostic] = []
    known = {str(h.get("function")) for h in (profile or {}).get("helpers", [])}
    ir, syntax_error = extract_exploit_ir(source, known_helpers=known)
    if syntax_error is not None:
        diagnostics.append(Diagnostic(
            code="EXP_PARSE_001",
            severity=SEVERITY_ERROR,
            confidence=1.0,
            message=f"EXP 语法错误（行 {syntax_error.lineno}）：{syntax_error.msg}",
            line=syntax_error.lineno or 0,
            evidence=[{"kind": "SYNTAX", "detail": syntax_error.msg}],
            impact="审计在此停止；修复语法后恢复。"))
        return [d.to_dict() for d in diagnostics]
    diagnostics.extend(run_rules(ir, bits=bits, pie=pie, profile=profile))
    result = [d.to_dict() for d in diagnostics]
    # 附带 each 诊断的可应用性快照 (编辑器据 hint 呈现 [Apply Fix])
    for item in result:
        item["fix_appliable"] = bool(item.get("suggested_fix") and item.get("fix_target"))
    return result
