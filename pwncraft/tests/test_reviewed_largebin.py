from pwncraft.features.audit.reviewed_largebin import (
    LargebinPointerWritePolicy,
    derive_largebin_pointer_write,
)


def _upstream(returned):
    return {
        "capabilities": ["controlled_tcache_allocation_target"],
        "facts": [{"kind": "reviewed_cache_pop_returns_target", "returned_user_address": returned}],
    }


def test_largebin_write_requires_exact_controlled_metadata_geometry():
    header = 0x555550004000
    target = 0x7FFFF7FC46A8
    inserted = 0x555550005000
    policy = LargebinPointerWritePolicy(
        name="reviewed largebin pointer write",
        allocator_family="glibc",
        allocator_version="reviewed-target",
        controlled_user_address=header + 0x20,
        large_chunk_header_address=header,
        fd_nextsize_value=header,
        bk_nextsize_value=target - 0x20,
        inserted_chunk_header_address=inserted,
        target_address=target,
        inserted_chunk_is_smaller=True,
        insertion_semantics_reviewed=True,
        target_writable_reviewed=True,
    )
    result = derive_largebin_pointer_write(_upstream(header + 0x20), policy)
    assert result is not None
    assert result["facts"][-1] == {
        "kind": "largebin_insertion_pointer_write",
        "address": target,
        "value": inserted,
        "width": 8,
    }
    assert result["capabilities"] == ["reviewed_largebin_pointer_write"]

    bad_target = LargebinPointerWritePolicy(**{**policy.__dict__, "bk_nextsize_value": target - 0x18})
    assert derive_largebin_pointer_write(_upstream(header + 0x20), bad_target) is None
    assert derive_largebin_pointer_write(_upstream(header + 0x30), policy) is None


def test_largebin_write_refuses_unreviewed_or_readonly_target():
    header = 0x1000
    base = dict(
        name="gate",
        allocator_family="glibc",
        allocator_version="x",
        controlled_user_address=0x1020,
        large_chunk_header_address=header,
        fd_nextsize_value=header,
        bk_nextsize_value=0x2000,
        inserted_chunk_header_address=0x3000,
        target_address=0x2020,
        inserted_chunk_is_smaller=True,
        insertion_semantics_reviewed=True,
        target_writable_reviewed=True,
    )
    policy = LargebinPointerWritePolicy(**base)
    assert derive_largebin_pointer_write(_upstream(0x1020), policy) is not None
    assert derive_largebin_pointer_write(
        _upstream(0x1020),
        LargebinPointerWritePolicy(**{**base, "target_writable_reviewed": False}),
    ) is None
