import json
from pathlib import Path

from pwncraft.features.audit.reviewed_freelist_stash_control import (
    SmallbinTcacheStashPolicy,
    derive_smallbin_tcache_stash_return,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-heapmage-9765b15f" / "expected_truth_cycle27.json"


def test_cycle27_official_stash_order_returns_fake_tcache_entries_user_on_third_pop():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    heap = 0x555550000000
    # Normalize the official labels while preserving V1,V2,V3,fake,p2,V4 traversal.
    v1, v2, v3 = heap + 0x1100, heap + 0x1200, heap + 0x1300
    fake = heap + truth["relative_policy"]["fake_user_heap_offset"]
    p2, v4 = heap + 0x1500, heap + 0x1600
    policy = SmallbinTcacheStashPolicy(
        name="sctf-heapmage-reviewed-stash",
        allocator_family="glibc", allocator_version="2.39",
        returned_head=heap + 0x1000,
        traversal_user_addresses=(v1, v2, v3, fake, p2, v4),
        tcache_count_before_stash=0, tcache_capacity=7,
        requested_pop_index=3, expected_return_address=fake,
        integrity_reviewed=True,
    )
    result = derive_smallbin_tcache_stash_return(
        {"bounded_adjacent_metadata_overwrite": True}, policy
    )
    assert result is not None
    assert result["facts"][1]["pop_order"][:3] == [v4, p2, fake]
    assert result["facts"][2]["returned_user_address"] == heap + 0x90


def test_cycle27_insufficient_tcache_room_blocks_stash_claim():
    policy = SmallbinTcacheStashPolicy(
        name="no-room", allocator_family="glibc", allocator_version="2.39",
        returned_head=0x1000, traversal_user_addresses=(0x1100,0x1200),
        tcache_count_before_stash=6, tcache_capacity=7,
        requested_pop_index=1, expected_return_address=0x1200,
        integrity_reviewed=True,
    )
    assert derive_smallbin_tcache_stash_return(
        {"bounded_adjacent_metadata_overwrite": True}, policy
    ) is None
