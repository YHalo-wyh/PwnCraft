"""Round-trip self-check: the generated EXP must pass the existing auditor.

VNext.6 口径：生成器输出重新喂回 ``audit_exp``，不允许出现 ERROR 级诊断。
CLEAN 只代表「没有确定性审计能证伪的结构问题」，不代表 EXP 已验证可利用。
"""
from __future__ import annotations

from pwncraft.features.audit.audit import audit_exp
from pwncraft.features.audit.model import SEVERITY_ERROR

VERDICT_CLEAN = "ROUND_TRIP_CLEAN"
VERDICT_ISSUES = "ROUND_TRIP_ISSUES"


def verify_exp(source: str, *, bits: int = 64, pie: bool = False) -> dict:
    diagnostics = audit_exp(str(source or ""), bits=bits, pie=pie)
    errors = [item for item in diagnostics if item.get("severity") == SEVERITY_ERROR]
    return {
        "verdict": VERDICT_CLEAN if not errors else VERDICT_ISSUES,
        "error_count": len(errors),
        "diagnostic_count": len(diagnostics),
        "diagnostics": diagnostics,
        "note": "CLEAN = 未发现确定性结构问题；可利用性仍需运行验证（UNVERIFIED）",
    }
