"""Evidence-first stack overflow truth model.

A cyclic offset is not automatically proof that saved RIP/EIP/PC is
controllable.  This module keeps static/pattern-derived facts separate from
runtime register observations so the Workbench can teach a real stack workflow
without silently upgrading a user-entered value into a control-flow primitive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .cyclic import cyclic_find

if TYPE_CHECKING:
    from .workspace import PwnWorkspace


_CONTROL_REGISTERS = {"rip", "eip", "pc"}


@dataclass(frozen=True)
class RuntimeRegisterObservation:
    """One debugger-observed register value at a concrete stop.

    The observation is intentionally tiny and transport-agnostic.  Pwndbg/GDB,
    a test fixture, or another debugger provider may populate it, but callers
    must name the register and value explicitly.  Merely reporting SIGSEGV is
    never enough to prove instruction-pointer control.
    """

    register: str
    value: str | int | bytes
    source: str = "pwndbg_runtime_register"
    signal: str = ""
    stop_reason: str = ""

    def __post_init__(self) -> None:
        register = str(self.register or "").strip().lower()
        if register not in _CONTROL_REGISTERS:
            raise ValueError(f"不是保存指令指针寄存器: {self.register}")
        if self.value in (None, "", b""):
            raise ValueError("运行时寄存器值为空")

    @property
    def normalized_register(self) -> str:
        return str(self.register or "").strip().lower()

    def to_dict(self) -> dict[str, object]:
        value = self.value.hex() if isinstance(self.value, bytes) else str(self.value)
        return {
            "register": self.normalized_register,
            "value": value,
            "source": str(self.source or "pwndbg_runtime_register"),
            "signal": str(self.signal or ""),
            "stop_reason": str(self.stop_reason or ""),
        }


@dataclass(frozen=True)
class StackOverflowEvidence:
    offset: int
    crash_value: str
    pattern_n: int | None = None
    source: str = "user_supplied_crash_value"
    control_register: str = ""
    control_value: str = ""
    runtime_signal: str = ""
    runtime_stop_reason: str = ""
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
            "control_value": str(self.control_value or ""),
            "runtime_signal": str(self.runtime_signal or ""),
            "runtime_stop_reason": str(self.runtime_stop_reason or ""),
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
    control_value: str | int | bytes | None = None,
    signal: str = "",
    stop_reason: str = "",
) -> StackOverflowEvidence:
    """Upgrade offset evidence only after RIP/EIP/PC overwrite is observed.

    This compatibility helper accepts already-derived offset evidence.  New
    runtime integrations should prefer :func:`derive_saved_ip_control_from_observation`,
    which derives the offset from the *observed register value itself* and thus
    cannot confirm control merely because a caller supplied a register name.
    """
    normalized = str(register or "").strip().lower()
    if normalized not in _CONTROL_REGISTERS:
        raise ValueError(f"不是保存指令指针寄存器: {register}")
    rendered_value = ""
    if isinstance(control_value, bytes):
        rendered_value = "0x" + control_value.hex()
    elif control_value is not None:
        rendered_value = str(control_value)
    return StackOverflowEvidence(
        offset=evidence.offset,
        crash_value=evidence.crash_value,
        pattern_n=evidence.pattern_n,
        source=str(source or evidence.source),
        control_register=normalized,
        control_value=rendered_value,
        runtime_signal=str(signal or ""),
        runtime_stop_reason=str(stop_reason or ""),
        state="confirmed_control",
    )


def derive_saved_ip_control_from_observation(
    observation: RuntimeRegisterObservation,
    *,
    n: int | None = None,
) -> StackOverflowEvidence:
    """Prove saved-IP control from an observed RIP/EIP/PC cyclic value.

    The decisive evidence is the debugger-observed control-register value.  We
    ask the same deterministic cyclic decoder used by the Stack page to locate
    that value.  If it is not present in the selected pattern, ``cyclic_find``
    raises and the caller must keep the capability UNKNOWN.
    """
    if not isinstance(observation, RuntimeRegisterObservation):
        raise TypeError("需要 RuntimeRegisterObservation")
    derived = derive_cyclic_overflow(
        observation.value,
        n=n,
        source=str(observation.source or "pwndbg_runtime_register"),
    )
    return confirm_saved_ip_control(
        derived,
        register=observation.normalized_register,
        source=str(observation.source or "pwndbg_runtime_register"),
        control_value=observation.value,
        signal=observation.signal,
        stop_reason=observation.stop_reason,
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
