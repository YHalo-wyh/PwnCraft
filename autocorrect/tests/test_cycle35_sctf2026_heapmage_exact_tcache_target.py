import json
from pathlib import Path

from pwncraft.features.audit.reviewed_tcache_metadata_target import (
    ExactTcacheMetadataTargetPolicy,
    derive_exact_tcache_metadata_target,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-heapmage-9765b15f" / "expected_truth_cycle35.json"


def _metadata_upstream(entries: int):
    return {
        "capabilities": ["reviewed_fake_user_allocation_acquired"],
        "facts": [
            {
                "kind": "nth_allocation_returns_reviewed_user",
                "returned_user_address": entries,
            }
        ],
    }


def _libc_upstream(base: int):
    return {
        "kind": "runtime_stdout_libc_base_derivation",
        "state": "observed_runtime",
        "runtime_observed": True,
        "capabilities": ["libc_base_derived_from_stdout_observation"],
        "facts": [
            {
                "kind": "libc_base_formula",
                "result": base,
            }
        ],
    }


def _policy(entries: int, base: int, target_offset: int):
    return ExactTcacheMetadataTargetPolicy(
        name="heapmage-wide-data-target",
        allocator_family="glibc",
        allocator_version="2.39",
        metadata_user_address=entries,
        tcache_entries_base=entries,
        target_entry_index=14,
        pointer_width=8,
        request_size=0xF0,
        chunk_size=0x100,
        target_libc_offset=target_offset,
        target_address=base + target_offset,
        alignment=16,
        tcache_count_positive_reviewed=True,
        entry_write_reviewed=True,
        allocation_semantics_reviewed=True,
    )


def test_cycle35_observed_libc_base_plus_entry14_returns_exact_wide_data_target():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    rel = truth["relative_policy"]
    heap = 0x555550000000
    entries = heap + rel["metadata_user_heap_offset"]
    libc = 0x7F4567000000
    target_offset = rel["first_target_libc_offset"]

    result = derive_exact_tcache_metadata_target(
        _metadata_upstream(entries),
        _libc_upstream(libc),
        _policy(entries, libc, target_offset),
    )
    assert result is not None
    assert result["facts"][0]["entry_index"] == 14
    assert result["facts"][0]["entry_address"] == heap + 0x100
    assert result["facts"][0]["value"] == libc + 0x204800
    assert result["facts"][1] == {
        "kind": "reviewed_tcache_target_alignment",
        "target_address": libc + 0x204800,
        "alignment": 16,
    }
    assert result["facts"][-1]["request_size"] == 0xF0
    assert result["facts"][-1]["returned_user_address"] == libc + 0x204800
    assert result["capabilities"] == ["reviewed_exact_tcache_allocation_target"]
    assert result["runtime_observed"] is True


def test_cycle35_static_candidate_without_observed_libc_base_stays_unknown():
    entries = 0x555550000090
    libc = 0x7F4567000000
    candidate = {
        "runtime_observed": False,
        "capabilities": ["stdout_partial_retarget_candidate"],
        "facts": [],
    }
    assert derive_exact_tcache_metadata_target(
        _metadata_upstream(entries), candidate, _policy(entries, libc, 0x204800)
    ) is None


def test_cycle35_wrong_metadata_user_stays_unknown():
    entries = 0x555550000090
    libc = 0x7F4567000000
    assert derive_exact_tcache_metadata_target(
        _metadata_upstream(entries + 0x10),
        _libc_upstream(libc),
        _policy(entries, libc, 0x204800),
    ) is None


def test_cycle35_wrong_libc_relative_target_stays_unknown():
    entries = 0x555550000090
    libc = 0x7F4567000000
    policy = _policy(entries, libc, 0x204800)
    bad = ExactTcacheMetadataTargetPolicy(
        **{**policy.__dict__, "target_address": libc + 0x204900}
    )
    assert derive_exact_tcache_metadata_target(
        _metadata_upstream(entries), _libc_upstream(libc), bad
    ) is None


def test_cycle35_unaligned_target_stays_unknown():
    entries = 0x555550000090
    libc = 0x7F4567000000
    policy = _policy(entries, libc, 0x204800)
    bad = ExactTcacheMetadataTargetPolicy(
        **{
            **policy.__dict__,
            "target_libc_offset": 0x204801,
            "target_address": libc + 0x204801,
        }
    )
    assert derive_exact_tcache_metadata_target(
        _metadata_upstream(entries), _libc_upstream(libc), bad
    ) is None


def test_cycle35_nonpositive_or_unreviewed_tcache_state_stays_unknown():
    entries = 0x555550000090
    libc = 0x7F4567000000
    policy = _policy(entries, libc, 0x204800)
    bad = ExactTcacheMetadataTargetPolicy(
        **{**policy.__dict__, "tcache_count_positive_reviewed": False}
    )
    assert derive_exact_tcache_metadata_target(
        _metadata_upstream(entries), _libc_upstream(libc), bad
    ) is None


def test_cycle35_does_not_promote_one_target_to_arbitrary_allocation():
    entries = 0x555550000090
    libc = 0x7F4567000000
    result = derive_exact_tcache_metadata_target(
        _metadata_upstream(entries),
        _libc_upstream(libc),
        _policy(entries, libc, 0x204800),
    )
    assert result is not None
    assert "arbitrary" not in " ".join(result["capabilities"]).lower()
    assert any("not unrestricted arbitrary allocation" in item for item in result["limitations"])
