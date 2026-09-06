from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleProposal:
    helper: str
    role: str
    expression: str
    evidence_count: int
    requires_confirmation: bool = True


def propose_exact_repeated_rule(helper: str, corrections: list[tuple[str, str]]) -> RuleProposal | None:
    """Only identical repeated mappings are proposed; one numeric pair never fits a formula."""

    if len(corrections) < 2 or len(set(corrections)) != 1:
        return None
    role, expression = corrections[0]
    return RuleProposal(helper, role, expression, len(corrections), True)
