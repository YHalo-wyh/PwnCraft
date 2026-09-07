import json
from pathlib import Path

from pwncraft.features.audit.reviewed_largebin import (
    LargebinPointerWritePolicy,
    derive_largebin_pointer_write,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-ubw-1b3b161e" / "expected_truth_cycle29.json"


def test_cycle29_official_relative_geometry_proves_stdout_pointer_write_only():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    a_header = 0x555550004000
    b_header = 0x555550005000
    stdout_ptr = 0x7F12342046A8
    controlled = a_header + 0x20
    upstream = {
        "capabilities": ["controlled_tcache_allocation_target"],
        "facts": [{"kind": "reviewed_cache_pop_returns_target", "returned_user_address": controlled}],
    }
    policy = LargebinPointerWritePolicy(
        name="sctf-ubw-largebin",
        allocator_family=truth["relative_policy"]["allocator_family"],
        allocator_version=truth["relative_policy"]["allocator_version"],
        controlled_user_address=controlled,
        large_chunk_header_address=a_header,
        fd_nextsize_value=a_header,
        bk_nextsize_value=stdout_ptr - 0x20,
        inserted_chunk_header_address=b_header,
        target_address=stdout_ptr,
        write_width=truth["relative_policy"]["write_width"],
        inserted_chunk_is_smaller=True,
        insertion_semantics_reviewed=True,
        target_writable_reviewed=True,
    )
    result = derive_largebin_pointer_write(upstream, policy)
    assert result is not None
    assert result["facts"][-1]["address"] == stdout_ptr
    assert result["facts"][-1]["value"] == b_header
    assert result["capabilities"] == ["reviewed_largebin_pointer_write"]
    assert "FSOP" not in " ".join(result["capabilities"])


def test_cycle29_wrong_bk_nextsize_target_relation_stays_unknown():
    a_header = 0x555550004000
    controlled = a_header + 0x20
    upstream = {
        "capabilities": ["controlled_tcache_allocation_target"],
        "facts": [{"kind": "reviewed_cache_pop_returns_target", "returned_user_address": controlled}],
    }
    policy = LargebinPointerWritePolicy(
        name="bad", allocator_family="glibc", allocator_version="reviewed",
        controlled_user_address=controlled, large_chunk_header_address=a_header,
        fd_nextsize_value=a_header, bk_nextsize_value=0x7000,
        inserted_chunk_header_address=0x6000, target_address=0x7030,
        inserted_chunk_is_smaller=True, insertion_semantics_reviewed=True,
        target_writable_reviewed=True,
    )
    assert derive_largebin_pointer_write(upstream, policy) is None
