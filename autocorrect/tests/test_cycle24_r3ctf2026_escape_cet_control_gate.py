import json
from pathlib import Path

from pwncraft.features.audit.reviewed_allocator_control import (
    ControlFlowEnforcementPolicy,
    assess_saved_return_control_under_policy,
)


ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "stack_control-r3ctf-2026-escape-cet-8950e5fd" / "expected_truth_cycle24.json"


def _truth():
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _policy():
    raw = dict(_truth()["reviewed_control_flow_policy"])
    raw.pop("runtime_arguments", None)
    raw.pop("provenance", None)
    raw["name"] = "r3ctf-escape-cet-reviewed-runtime"
    return ControlFlowEnforcementPolicy(**raw)


def test_cycle24_saved_rip_only_candidate_stays_blocked_under_reviewed_cet_runtime():
    result = assess_saved_return_control_under_policy(
        {"saved_rip_overwrite": True}, _policy()
    )
    assert result["saved_rip_overwrite"] is True
    assert result["executable_control"] is False
    assert result["blockers"] == ["shadow_stack_return_mismatch"]
    assert result["policy"]["runtime_engine"] == "Intel SDE 10.8.0"


def test_cycle24_indirect_target_without_endbr_evidence_stays_blocked():
    result = assess_saved_return_control_under_policy(
        {
            "saved_rip_overwrite": True,
            "shadow_stack_sync_evidence": True,
            "uses_indirect_branch": True,
            "indirect_target_endbr_evidence": False,
        },
        _policy(),
    )
    assert result["executable_control"] is False
    assert "ibt_target_without_reviewed_endbr" in result["blockers"]


def test_cycle24_does_not_claim_bypass_or_exploit_success():
    result = assess_saved_return_control_under_policy(
        {"saved_rip_overwrite": True}, _policy()
    )
    text = json.dumps(result, ensure_ascii=False).lower()
    assert "exploit success" in text
    assert "cet bypass" not in text
    assert result["runtime_observed"] is False
