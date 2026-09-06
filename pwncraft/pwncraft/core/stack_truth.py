"""Evidence-first stack overflow truth model.

A cyclic offset is not automatically proof that saved RIP/EIP is controllable.
This module keeps those facts separate so the Workbench can teach the normal
stack workflow without silently upgrading a user-entered pattern value into a
confirmed control-flow primitive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .cyclic import cyclic_find

if TYPE_CHECKING:
    from .workspace import PwnWorkspace


_CONTROL_REGISTERS = {"rip", "eip", "pc"}


@dataclass(frozen=True)
class StackOverflowEvidence:
    offset: int
    crash_value: str
    pattern_n: int | None = None
    source: str = "user_supplied_crash_value"
    control_register: str = ""
    state: str = "offset_only"  # offset_only | confirmed_control

    def __post_init__(self) -> None:
        if int(self.offset) < 0:
            raise ValueError("stack overflow offset 不能为负数")
        register = str(self.control_register or "").strip().lower()
        if self.state == "confirmed_control" and register not in _CONTROL_REGISTERS:
            raise ValueError("confirmed_control 必须明确 RIP/EIP/PC 证据")

    def to_dict(self) -> dict[str, object]:
        return {
            "overflow_offset": int(self.offset),
            "overflow_crash_value": self.crash_value,
            "overflow_pattern_n": self.pattern_n,
            "overflow_source": self.source,
            "overflow_evidence_state": self.state,
            "control_register": str(self.control_register or "").strip().lower(),
        }


def derive_cyclic_overflow(
    crash_value: str | int | bytes,
    *,
    n: int | None = None,
    source: str = "user_supplied_crash_value",
) -> StackOverflowEvidence:
    """Derive only the cyclic offset; do not claim saved-IP control."""
    offset = cyclic_find(crash_value, n=n)
    return StackOverflowEvidence(
        offset=offset,
        crash_value=str(crash_value),
        pattern_n=n,
        source=str(source or "user_supplied_crash_value"),
        state="offset_only",
    )


def confirm_saved_ip_control(
    evidence: StackOverflowEvidence,
    *,
    register: str,
    source: str = "runtime_register_observation",
) -> StackOverflowEvidence:
    """Upgrade offset evidence only after RIP/EIP/PC overwrite is observed."""
    normalized = str(register or "").strip().lower()
    if normalized not in _CONTROL_REGISTERS:
        raise ValueError(f"不是保存指令指针寄存器: {register}")
    return StackOverflowEvidence(
        offset=evidence.offset,
        crash_value=evidence.crash_value,
        pattern_n=evidence.pattern_n,
        source=str(source or evidence.source),
        control_register=normalized,
        state="confirmed_control",
    )


def publish_stack_evidence(workspace: "PwnWorkspace", evidence: StackOverflowEvidence) -> dict[str, object]:
    """Publish JSON-safe stack truth into the shared Workspace."""
    payload = evidence.to_dict()
    workspace.update_section("stack", payload, event="stack_changed")
    return payload


def stack_control_state(workspace: "PwnWorkspace") -> str:
    stack = workspace.stack if isinstance(workspace.stack, dict) else {}
    if stack.get("overflow_offset") is None:
        return "unknown"
    state = str(stack.get("overflow_evidence_state") or "").strip().lower()
    register = str(stack.get("control_register") or "").strip().lower()
    if state == "confirmed_control" and register in _CONTROL_REGISTERS:
        return "confirmed_control"
    if not state:
        # Pre-cycle-7 saved projects stored only overflow_offset.  Keep their
        # historical semantics available to callers without pretending the new
        # provenance fields existed.
        return "legacy_offset"
    return "offset_only"
