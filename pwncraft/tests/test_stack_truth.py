import pytest

from pwncraft.core.capability import analyze_capabilities
from pwncraft.core.cyclic import cyclic_pattern
from pwncraft.core.pwn_surface import PwnDomain, analyze_pwn_surface
from pwncraft.core.stack_truth import (
    confirm_saved_ip_control,
    derive_cyclic_overflow,
    publish_stack_evidence,
    stack_control_state,
)
from pwncraft.core.workspace import PwnWorkspace


def _cap(workspace: PwnWorkspace, name: str):
    return {item.name: item for item in analyze_capabilities(workspace)}[name]


def _surface(workspace: PwnWorkspace, domain: PwnDomain):
    return {item.domain: item for item in analyze_pwn_surface(workspace)}[domain]


def test_cyclic_derivation_is_offset_only_not_control_rip() -> None:
    pattern = cyclic_pattern(256, n=4)
    evidence = derive_cyclic_overflow(pattern[72:76], n=4, source="crash-value")
    assert evidence.offset == 72
    assert evidence.state == "offset_only"
    assert evidence.control_register == ""

    workspace = PwnWorkspace()
    publish_stack_evidence(workspace, evidence)
    assert stack_control_state(workspace) == "offset_only"
    assert _cap(workspace, "Control RIP").state == "unknown"
    assert _surface(workspace, PwnDomain.STACK).state == "evidenced"
    assert _surface(workspace, PwnDomain.CONTROL_FLOW).state == "unknown"


def test_runtime_saved_ip_observation_upgrades_control_rip() -> None:
    pattern = cyclic_pattern(256, n=4)
    offset_only = derive_cyclic_overflow(pattern[72:76], n=4)
    confirmed = confirm_saved_ip_control(
        offset_only,
        register="RIP",
        source="pwndbg register observation",
    )
    workspace = PwnWorkspace()
    publish_stack_evidence(workspace, confirmed)

    assert stack_control_state(workspace) == "confirmed_control"
    capability = _cap(workspace, "Control RIP")
    assert capability.state == "available"
    assert any("RIP overwrite observed" in reason for reason in capability.reasons)
    assert _surface(workspace, PwnDomain.CONTROL_FLOW).state == "evidenced"


def test_confirm_saved_ip_rejects_non_instruction_pointer_register() -> None:
    pattern = cyclic_pattern(128, n=4)
    evidence = derive_cyclic_overflow(pattern[40:44], n=4)
    with pytest.raises(ValueError, match="不是保存指令指针寄存器"):
        confirm_saved_ip_control(evidence, register="rax")


def test_legacy_bare_overflow_offset_remains_compatible() -> None:
    workspace = PwnWorkspace()
    workspace.stack["overflow_offset"] = 72
    assert stack_control_state(workspace) == "legacy_offset"
    capability = _cap(workspace, "Control RIP")
    assert capability.state == "available"
    assert any("legacy workspace fact" in reason for reason in capability.reasons)


def test_nonempty_plt_is_not_format_string_evidence() -> None:
    workspace = PwnWorkspace()
    workspace.symbols["plt"] = {"puts": 0x401020, "printf": 0x401030}
    capabilities = {item.name: item for item in analyze_capabilities(workspace)}
    assert "Format String" not in capabilities
    assert _surface(workspace, PwnDomain.FORMAT_STRING).state == "unknown"


def test_explicit_format_offset_is_evidence_but_not_arbitrary_write_proof() -> None:
    workspace = PwnWorkspace()
    workspace.exploit["format_offset"] = 8
    capability = _cap(workspace, "Format String")
    assert capability.state == "unknown"
    assert "format_offset=8" in capability.reasons
    assert _surface(workspace, PwnDomain.MEMORY_WRITE).state == "unknown"
