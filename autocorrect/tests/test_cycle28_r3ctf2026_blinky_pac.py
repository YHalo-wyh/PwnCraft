import json
from pathlib import Path

from pwncraft.features.audit.reviewed_freelist_stash_control import (
    PacSpeculationPolicy,
    derive_pac_speculative_tag_oracle,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "control_flow-r3ctf-2026-blinky-pac" / "expected_truth_cycle28.json"


def _policy(**overrides):
    raw = dict(json.loads(TRUTH.read_text(encoding="utf-8"))["reviewed_pac_policy"])
    raw.pop("provenance", None)
    raw["name"] = "r3ctf-blinky-reviewed-pac-oracle"
    raw.update(overrides)
    return PacSpeculationPolicy(**raw)


def test_cycle28_official_pac_oracle_has_exact_256_candidate_search_space_and_target():
    result = derive_pac_speculative_tag_oracle(_policy())
    assert result is not None
    assert result["facts"][0]["candidate_count"] == 256
    assert result["facts"][1]["tag_bits"] == 8
    assert result["facts"][2]["target_address"] == 0x2030
    assert result["capabilities"] == ["pac_tag_recoverable_via_reviewed_timing_oracle"]


def test_cycle28_bad_guess_that_commits_fault_is_not_a_silent_oracle():
    assert derive_pac_speculative_tag_oracle(
        _policy(speculative_bad_tag_commits_fault=True)
    ) is None


def test_cycle28_known_target_without_oracle_does_not_become_reachable():
    assert derive_pac_speculative_tag_oracle(
        _policy(good_tag_speculative_loads_probe=False)
    ) is None
