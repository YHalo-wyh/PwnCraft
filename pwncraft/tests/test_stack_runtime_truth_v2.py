import pytest

from pwncraft.core.capability import analyze_capabilities
from pwncraft.core.cyclic import cyclic_pattern
from pwncraft.core.stack_truth import (
    RuntimeRegisterObservation,
    derive_saved_ip_control_from_observation,
    publish_stack_evidence,
)
from pwncraft.core.workspace import PwnWorkspace


def _cap(workspace: PwnWorkspace, name: str):
    return {item.name: item for item in analyze_capabilities(workspace)}[name]


def test_observed_rip_value_proves_offset_and_control() -> None:
    pattern = cyclic_pattern(512, n=8)
    register_bytes = pattern[120:128]
    register_value = int.from_bytes(register_bytes, "little")
    evidence = derive_saved_ip_control_from_observation(
        RuntimeRegisterObservation(
            register="RIP",
            value=register_value,
            source="pwndbg stop event",
            signal="SIGSEGV",
            stop_reason="SignalEvent",
        ),
        n=8,
    )
    assert evidence.offset == 120
    assert evidence.state == "confirmed_control"
    assert evidence.control_register == "rip"
    assert evidence.control_value == str(register_value)
    assert evidence.runtime_signal == "SIGSEGV"
    assert evidence.runtime_stop_reason == "SignalEvent"

    workspace = PwnWorkspace()
    publish_stack_evidence(workspace, evidence)
    assert _cap(workspace, "Control RIP").state == "available"


def test_observed_eip_value_works_for_n4_pattern() -> None:
    pattern = cyclic_pattern(256, n=4)
    register_value = int.from_bytes(pattern[72:76], "little")
    evidence = derive_saved_ip_control_from_observation(
        RuntimeRegisterObservation(register="eip", value=register_value),
        n=4,
    )
    assert evidence.offset == 72
    assert evidence.control_register == "eip"


def test_non_pattern_rip_never_confirms_control() -> None:
    observation = RuntimeRegisterObservation(register="rip", value=0x4141414141414141)
    with pytest.raises(ValueError, match="不在 n="):
        derive_saved_ip_control_from_observation(observation, n=8)


def test_non_control_register_is_rejected_before_derivation() -> None:
    with pytest.raises(ValueError, match="不是保存指令指针寄存器"):
        RuntimeRegisterObservation(register="rax", value=0x41414141)


def test_signal_without_control_register_value_is_not_evidence() -> None:
    with pytest.raises(ValueError, match="运行时寄存器值为空"):
        RuntimeRegisterObservation(register="rip", value="", signal="SIGSEGV")
