import json
from pathlib import Path

from pwncraft.features.audit.reviewed_allocator_leak import (
    StdoutLow16CandidatePolicy,
    UnsortedTcacheLibcSeedPolicy,
    derive_libc_base_from_stdout_observation,
    derive_stdout_low16_candidate,
    derive_unsorted_tcache_libc_seed,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-heapmage-9765b15f" / "expected_truth_cycle31.json"


def test_cycle31_relative_heap_geometry_seeds_libc_pointer_then_only_candidate_stdout():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    rel = truth["relative_policy"]
    heap = 0x555550000000
    entries = heap + rel["metadata_user_heap_offset"]
    fake_user = heap + rel["target_entry_heap_offset"]
    upstream = {
        "capabilities": ["reviewed_fake_user_allocation_acquired"],
        "facts": [{"kind": "nth_allocation_returns_reviewed_user", "returned_user_address": entries}],
    }
    seed = derive_unsorted_tcache_libc_seed(upstream, UnsortedTcacheLibcSeedPolicy(
        name="heapmage-unsorted-seed",
        allocator_family=rel["allocator_family"],
        allocator_version=rel["allocator_version"],
        acquired_metadata_user_address=entries,
        tcache_entries_base=entries,
        fake_user_address=fake_user,
        fake_chunk_header_address=heap + rel["fake_chunk_header_heap_offset"],
        chunk_header_size=0x10,
        fake_chunk_size=rel["fake_chunk_size"],
        target_entry_index=rel["target_entry_index"],
        pointer_width=rel["pointer_width"],
        tcache_count_before_free=7,
        tcache_capacity=7,
        unsorted_insert_reviewed=True,
        libc_pointer_write_reviewed=True,
    ))
    assert seed is not None
    assert seed["capabilities"] == ["libc_pointer_seeded_in_tcache_metadata"]

    candidate = derive_stdout_low16_candidate(seed, StdoutLow16CandidatePolicy(
        name="heapmage-stdout-candidate",
        tcache_entries_base=entries,
        target_entry_index=14,
        pointer_width=8,
        libc_low_nibble_guess=5,
        stdout_symbol_offset=0x2045C0,
    ))
    assert candidate is not None
    assert candidate["facts"][1]["candidate_count"] == 16
    assert candidate["runtime_observed"] is False


def test_cycle31_libc_base_appears_only_after_observed_stdout_relative_pointer():
    stdout_off = 0x2045C0
    field_off = 0x84
    base = 0x7F4567000000
    observed = base + stdout_off + field_off
    result = derive_libc_base_from_stdout_observation(
        observed,
        stdout_symbol_offset=stdout_off,
        observed_field_offset=field_off,
    )
    assert result is not None
    assert result["facts"][1]["result"] == base
    assert result["runtime_observed"] is True
