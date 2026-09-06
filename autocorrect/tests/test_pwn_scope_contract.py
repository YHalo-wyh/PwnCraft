import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _scope():
    return json.loads((ROOT / "pwn_scope.json").read_text(encoding="utf-8"))


def test_scope_is_general_pwn_not_heap_only() -> None:
    data = _scope()
    assert data["scope"] == "general_pwn_workbench"
    domains = data["domains"]
    for name in ("stack", "heap", "format_string", "control_flow", "leak", "syscall_sandbox"):
        assert name in domains
    assert len(domains) >= 8


def test_scheduler_interleaves_heap_and_non_heap_lanes() -> None:
    scheduler = _scope()["scheduler"]
    assert scheduler["policy"] == "cross_domain_interleave"
    active = scheduler["active_lanes"]
    assert any(item.startswith("heap_") for item in active)
    assert any(not item.startswith("heap_") for item in active)


def test_hard_rules_forbid_global_claims_from_one_domain() -> None:
    rules = "\n".join(_scope()["hard_rules"])
    assert "不得把 heap lane 的 MATCH 外推为整个 PwnCraft 已闭环" in rules
    assert "没有证据时保持 unknown" in rules
