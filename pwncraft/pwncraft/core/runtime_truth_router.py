"""Route structured debugger machine messages into shared Workspace truth.

This module deliberately consumes *machine messages*, not terminal text.  It is
small enough to be reused by Electron, Qt compatibility code, tests or future
remote-debug transports without teaching any UI how to scrape pwndbg output.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .stack_truth import (
    RuntimeRegisterObservation,
    derive_saved_ip_control_from_observation,
    publish_stack_evidence,
)

if TYPE_CHECKING:
    from .workspace import PwnWorkspace


@dataclass(frozen=True)
class RuntimeTruthResult:
    message_type: str
    status: str  # applied | observed_only | ignored
    domain: str = ""
    reason: str = ""
    facts: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "message_type": self.message_type,
            "status": self.status,
            "domain": self.domain,
            "reason": self.reason,
            "facts": dict(self.facts or {}),
        }


def apply_machine_message(
    workspace: "PwnWorkspace",
    message_type: str,
    payload: Mapping[str, object] | None,
    *,
    pattern_n: int | None = None,
) -> RuntimeTruthResult:
    """Apply one structured debugger fact without inventing missing evidence."""
    kind = str(message_type or "").strip()
    data = dict(payload or {})
    if kind != "stack_register_observation":
        return RuntimeTruthResult(kind, "ignored", reason="no truth router for message type")

    # Preserve the raw observation even when it does not prove a cyclic
    # overwrite.  This makes the UI/debug log auditable while keeping Stack
    # capability UNKNOWN until the stronger correlation succeeds.
    observed = {
        "register": str(data.get("register") or "").strip().lower(),
        "value": data.get("value"),
        "value_hex": str(data.get("value_hex") or ""),
        "source": str(data.get("source") or "PWNDBG_GDB_REGISTER"),
        "provenance": str(data.get("provenance") or "OBSERVED_RUNTIME"),
        "signal": str(data.get("signal") or ""),
        "stop_reason": str(data.get("stop_reason") or ""),
    }
    workspace.set_runtime(observed=True, stack_register_observation=observed)

    try:
        observation = RuntimeRegisterObservation(
            register=observed["register"],
            value=observed["value"],
            source=observed["source"],
            signal=observed["signal"],
            stop_reason=observed["stop_reason"],
        )
        evidence = derive_saved_ip_control_from_observation(observation, n=pattern_n)
    except (TypeError, ValueError) as error:
        return RuntimeTruthResult(
            kind,
            "observed_only",
            domain="stack",
            reason=f"register observed but saved-IP control not proven: {error}",
            facts=observed,
        )

    facts = publish_stack_evidence(workspace, evidence)
    return RuntimeTruthResult(
        kind,
        "applied",
        domain="stack",
        reason="observed control register correlates with cyclic pattern",
        facts=facts,
    )
