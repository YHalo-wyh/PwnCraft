from pwncraft.core.pwn_surface import PwnDomain, active_domains, analyze_pwn_surface, surface_summary
from pwncraft.core.workspace import PwnWorkspace


def _by_domain(workspace: PwnWorkspace):
    return {item.domain: item for item in analyze_pwn_surface(workspace)}


def test_empty_workspace_does_not_default_to_heap() -> None:
    workspace = PwnWorkspace()
    domains = _by_domain(workspace)
    assert domains[PwnDomain.HEAP].state == "unknown"
    assert domains[PwnDomain.STACK].state == "unknown"
    assert active_domains(workspace) == ()


def test_stack_offset_activates_stack_and_control_flow_without_heap_bias() -> None:
    workspace = PwnWorkspace()
    workspace.stack["overflow_offset"] = 72
    domains = _by_domain(workspace)
    assert domains[PwnDomain.STACK].state == "evidenced"
    assert "overflow_offset=72" in domains[PwnDomain.STACK].evidence
    assert domains[PwnDomain.CONTROL_FLOW].state == "evidenced"
    assert domains[PwnDomain.HEAP].state == "unknown"
    assert "stack" in active_domains(workspace)
    assert "heap" not in active_domains(workspace)


def test_heap_model_facts_are_partial_until_a_heap_primitive_is_recorded() -> None:
    workspace = PwnWorkspace()
    workspace.heap.update({"step": 4, "chunks": [{"chunk_id": "A"}], "bins": {}})
    domains = _by_domain(workspace)
    assert domains[PwnDomain.HEAP].state == "partial"

    workspace.exploit["primitives"] = [{"name": "Heap UAF"}]
    domains = _by_domain(workspace)
    assert domains[PwnDomain.HEAP].state == "evidenced"
    assert domains[PwnDomain.STACK].state == "unknown"


def test_format_write_is_cross_classified_as_format_and_generic_write() -> None:
    workspace = PwnWorkspace()
    workspace.exploit["primitives"] = [{"name": "Format String Write"}]
    domains = _by_domain(workspace)
    assert domains[PwnDomain.FORMAT_STRING].state == "evidenced"
    assert domains[PwnDomain.MEMORY_WRITE].state == "evidenced"
    assert domains[PwnDomain.HEAP].state == "unknown"


def test_seccomp_and_leak_are_independent_surfaces() -> None:
    workspace = PwnWorkspace()
    workspace.set_seccomp_policy({"execve": "BLOCKED", "openat": "ALLOWED"}, source="seccomp-tools")
    workspace.leaks.append({"symbol": "puts", "address": 0x7F0000000000})
    domains = _by_domain(workspace)
    assert domains[PwnDomain.SYSCALL_SANDBOX].state == "evidenced"
    assert domains[PwnDomain.LEAK].state == "evidenced"
    assert domains[PwnDomain.STACK].state == "unknown"
    assert domains[PwnDomain.HEAP].state == "unknown"


def test_surface_summary_exposes_full_project_catalog() -> None:
    summary = surface_summary(PwnWorkspace())
    assert set(summary["catalog"]) == {domain.value for domain in PwnDomain}
    assert "stack" in summary["catalog"]
    assert "heap" in summary["catalog"]
    assert "format_string" in summary["catalog"]
    assert summary["active_domains"] == []
