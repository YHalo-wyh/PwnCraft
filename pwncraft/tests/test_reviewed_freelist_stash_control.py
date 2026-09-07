from pwncraft.features.audit.reviewed_freelist_stash_control import (
    PacSpeculationPolicy,
    SafeLinkedFreelistPolicy,
    SmallbinTcacheStashPolicy,
    derive_pac_speculative_tag_oracle,
    derive_safe_linked_freelist_return,
    derive_smallbin_tcache_stash_return,
)


def test_safe_linked_freelist_requires_exact_encoding_and_upstream_state():
    storage = 0x555550001000
    target = 0x555550002000
    policy = SafeLinkedFreelistPolicy(
        name="reviewed safe-linked tcache edge",
        allocator_family="glibc",
        allocator_version="reviewed-target",
        safe_linking_enabled=True,
        pointer_shift=12,
        alignment=16,
        storage_address=storage,
        encoded_next=target ^ (storage >> 12),
        target_user_address=target,
        cache_count_before_pop=2,
        required_pop_index=2,
    )
    upstream = {"capabilities": ["same_identity_cross_bin_membership"]}
    result = derive_safe_linked_freelist_return(upstream, policy)
    assert result is not None
    assert result["capabilities"] == ["controlled_tcache_allocation_target"]
    assert result["facts"][-1]["returned_user_address"] == target

    bad = SafeLinkedFreelistPolicy(**{**policy.__dict__, "encoded_next": policy.encoded_next ^ 1})
    assert derive_safe_linked_freelist_return(upstream, bad) is None
    assert derive_safe_linked_freelist_return({"capabilities": []}, policy) is None


def test_smallbin_stash_uses_reviewed_traversal_and_lifo_only():
    traversal = (0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1600)
    policy = SmallbinTcacheStashPolicy(
        name="reviewed smallbin stash",
        allocator_family="glibc",
        allocator_version="2.39",
        returned_head=0x1000,
        traversal_user_addresses=traversal,
        tcache_count_before_stash=0,
        tcache_capacity=7,
        requested_pop_index=3,
        expected_return_address=0x1400,
        integrity_reviewed=True,
    )
    result = derive_smallbin_tcache_stash_return(
        {"bounded_adjacent_metadata_overwrite": True}, policy
    )
    assert result is not None
    assert result["facts"][1]["pop_order"] == list(reversed(traversal))
    assert result["facts"][2]["returned_user_address"] == 0x1400
    assert result["capabilities"] == ["reviewed_fake_user_allocation_acquired"]

    no_integrity = SmallbinTcacheStashPolicy(**{**policy.__dict__, "integrity_reviewed": False})
    assert derive_smallbin_tcache_stash_return(
        {"bounded_adjacent_metadata_overwrite": True}, no_integrity
    ) is None


def test_pac_speculation_oracle_requires_asymmetric_cache_effect_without_committed_fault():
    policy = PacSpeculationPolicy(
        name="reviewed MIPS PAC speculative oracle",
        architecture="MIPS64r6",
        protected_region_start=0x2000,
        protected_region_end=0x100000,
        tag_bits=8,
        tag_high_bit=63,
        probe_address=0x1000,
        target_address=0x2030,
        good_tag_speculative_loads_probe=True,
        bad_tag_speculative_loads_probe=False,
        speculative_bad_tag_commits_fault=False,
        timing_hit_distinguishable=True,
    )
    result = derive_pac_speculative_tag_oracle(policy)
    assert result is not None
    assert result["facts"][0]["candidate_count"] == 256
    assert result["facts"][2]["target_address"] == 0x2030
    assert result["capabilities"] == ["pac_tag_recoverable_via_reviewed_timing_oracle"]

    noisy = PacSpeculationPolicy(**{**policy.__dict__, "timing_hit_distinguishable": False})
    assert derive_pac_speculative_tag_oracle(noisy) is None
