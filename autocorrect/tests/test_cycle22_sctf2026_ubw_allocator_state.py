import json
from pathlib import Path

from pwncraft.features.audit.reviewed_allocator_control import (
    ResizedDoubleReleasePolicy,
    derive_resized_double_release_bins,
)


ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-ubw-1b3b161e" / "expected_truth_cycle22.json"


def _truth():
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _alias_chain():
    return {
        "aliased_expression": "arr[0]",
        "conditional_double_release": True,
        "facts": [{"kind": "conditional_double_release_same_identity", "identity": "arr[0]"}],
    }


def _policy(**overrides):
    raw = dict(_truth()["reviewed_allocator_state_policy"])
    raw.pop("provenance", None)
    raw["name"] = "sctf-ubw-reviewed-resized-double-release"
    raw.update(overrides)
    return ResizedDoubleReleasePolicy(**raw)


def test_cycle22_truth_derives_exact_reviewed_cross_bin_relation():
    result = derive_resized_double_release_bins(_alias_chain(), _policy())
    assert result is not None
    assert result["facts"][0]["destination"] == "unsorted"
    assert result["facts"][1]["old_chunk_size"] == 0xA0
    assert result["facts"][1]["new_chunk_size"] == 0xF0
    assert result["facts"][2]["destination"] == "tcache"
    assert result["capabilities"] == ["same_identity_cross_bin_membership"]
    assert result["runtime_observed"] is False


def test_cycle22_does_not_guess_first_release_bin_when_tcache_is_not_full():
    assert derive_resized_double_release_bins(
        _alias_chain(), _policy(first_sizeclass_cache_count=6)
    ) is None


def test_cycle22_does_not_promote_cross_bin_membership_to_poisoning():
    result = derive_resized_double_release_bins(_alias_chain(), _policy())
    assert result is not None
    text = json.dumps(result, ensure_ascii=False).lower()
    assert "same_identity_cross_bin_membership" in text
    assert "arbitrary allocation" not in result["capabilities"]
    assert "tcache poisoning" not in result["capabilities"]
