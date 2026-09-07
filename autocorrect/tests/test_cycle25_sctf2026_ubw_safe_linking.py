import json
from pathlib import Path

from pwncraft.features.audit.reviewed_freelist_stash_control import (
    SafeLinkedFreelistPolicy,
    derive_safe_linked_freelist_return,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-ubw-1b3b161e" / "expected_truth_cycle25.json"


def test_cycle25_official_expression_decodes_to_reviewed_target_and_second_pop():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    # Normalize ASLR-dependent symbols while preserving the official algebra.
    p0 = 0x555550001000
    a = 0x555550003FF0
    target = a + 0x10
    encoded = target ^ (p0 >> truth["symbolic_policy"]["pointer_shift"])
    policy = SafeLinkedFreelistPolicy(
        name="sctf-ubw-safe-link",
        allocator_family="glibc",
        allocator_version="official-target-reviewed",
        safe_linking_enabled=True,
        pointer_shift=12,
        alignment=16,
        storage_address=p0,
        encoded_next=encoded,
        target_user_address=target,
        cache_count_before_pop=2,
        required_pop_index=2,
    )
    result = derive_safe_linked_freelist_return(
        {"capabilities": ["same_identity_cross_bin_membership"]}, policy
    )
    assert result is not None
    assert result["facts"][-1]["returned_user_address"] == target
    assert result["capabilities"] == ["controlled_tcache_allocation_target"]


def test_cycle25_wrong_safe_link_encoding_stays_unknown():
    p0, target = 0x555550001000, 0x555550004000
    policy = SafeLinkedFreelistPolicy(
        name="bad-safe-link", allocator_family="glibc", allocator_version="reviewed",
        safe_linking_enabled=True, pointer_shift=12, alignment=16,
        storage_address=p0, encoded_next=(target ^ (p0 >> 12)) + 1,
        target_user_address=target, cache_count_before_pop=2, required_pop_index=2,
    )
    assert derive_safe_linked_freelist_return(
        {"capabilities": ["same_identity_cross_bin_membership"]}, policy
    ) is None
