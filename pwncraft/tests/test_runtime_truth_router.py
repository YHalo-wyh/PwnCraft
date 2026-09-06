from pwncraft.core.capability import analyze_capabilities
from pwncraft.core.cyclic import cyclic_pattern
from pwncraft.core.runtime_truth_router import apply_machine_message
from pwncraft.core.workspace import PwnWorkspace


def _control_state(workspace: PwnWorkspace) -> str:
    return {item.name: item for item in analyze_capabilities(workspace)}["Control RIP"].state


def test_structured_stack_register_message_routes_to_confirmed_control() -> None:
    pattern = cyclic_pattern(512, n=8)
    value = int.from_bytes(pattern[96:104], "little")
    workspace = PwnWorkspace()
    result = apply_machine_message(
        workspace,
        "stack_register_observation",
        {
            "register": "rip",
            "value": value,
            "value_hex": hex(value),
            "source": "PWNDBG_GDB_REGISTER",
            "provenance": "OBSERVED_RUNTIME",
            "signal": "SIGSEGV",
            "stop_reason": "SignalEvent",
        },
        pattern_n=8,
    )
    assert result.status == "applied"
    assert workspace.stack["overflow_offset"] == 96
    assert workspace.stack["overflow_evidence_state"] == "confirmed_control"
    assert workspace.runtime["stack_register_observation"]["provenance"] == "OBSERVED_RUNTIME"
    assert _control_state(workspace) == "available"


def test_nonpattern_register_is_preserved_but_does_not_claim_control() -> None:
    workspace = PwnWorkspace()
    result = apply_machine_message(
        workspace,
        "stack_register_observation",
        {"register": "rip", "value": 0x4141414141414141, "signal": "SIGSEGV"},
        pattern_n=8,
    )
    assert result.status == "observed_only"
    assert "stack_register_observation" in workspace.runtime
    assert workspace.stack.get("overflow_evidence_state") is None
    assert _control_state(workspace) == "unknown"


def test_unrelated_machine_message_is_ignored() -> None:
    workspace = PwnWorkspace()
    result = apply_machine_message(workspace, "session_state", {"state": "READY"})
    assert result.status == "ignored"
    assert not workspace.runtime
