from pwncraft.features.audit.reviewed_allocator_control import (
    AdjacentChunkMetadataPolicy,
    ControlFlowEnforcementPolicy,
    ResizedDoubleReleasePolicy,
    assess_saved_return_control_under_policy,
    derive_adjacent_chunk_metadata_overwrite,
    derive_resized_double_release_bins,
)


def _alias_chain():
    return {
        "aliased_expression": "arr[0]",
        "conditional_double_release": True,
        "facts": [
            {
                "kind": "conditional_double_release_same_identity",
                "identity": "arr[0]",
                "condition": "realloc moves allocation and frees old storage",
            }
        ],
    }


def _ubw_policy(**overrides):
    values = dict(
        name="reviewed glibc resized double release",
        allocator_family="glibc",
        allocator_version="reviewed-target",
        initial_chunk_size=0xA0,
        adjacent_free_chunk_size=0x50,
        first_sizeclass_cache_count=7,
        first_sizeclass_cache_capacity=7,
        first_cache_bypass_destination="unsorted",
        forward_consolidation_reviewed=True,
        consolidated_chunk_size=0xF0,
        second_sizeclass_cache_count=6,
        second_sizeclass_cache_capacity=7,
        second_cache_destination="tcache",
    )
    values.update(overrides)
    return ResizedDoubleReleasePolicy(**values)


def test_resized_double_release_derives_cross_bin_membership_only_with_allocator_state():
    result = derive_resized_double_release_bins(_alias_chain(), _ubw_policy())
    assert result is not None
    assert result["allocator"]["family"] == "glibc"
    assert result["capabilities"] == ["same_identity_cross_bin_membership"]
    assert [fact["kind"] for fact in result["facts"]] == [
        "first_release_cache_bypass",
        "forward_consolidation_changes_chunk_size",
        "second_release_uses_resized_header",
        "same_identity_cross_bin_membership",
    ]
    assert result["facts"][1]["old_chunk_size"] == 0xA0
    assert result["facts"][1]["new_chunk_size"] == 0xF0


def test_resized_double_release_stays_unknown_when_first_cache_not_full():
    assert derive_resized_double_release_bins(
        _alias_chain(), _ubw_policy(first_sizeclass_cache_count=6)
    ) is None


def test_resized_double_release_requires_upstream_alias_double_release_fact():
    chain = _alias_chain()
    chain["facts"] = []
    assert derive_resized_double_release_bins(chain, _ubw_policy()) is None


def _metadata_policy():
    return AdjacentChunkMetadataPolicy(
        name="reviewed bounded adjacent chunk metadata overwrite",
        allocator_family="glibc",
        allocator_version="2.39",
        user_capacity=0xC0,
        maximum_write_length=0xF0,
        metadata_fields=(
            ("prev_size", 0xC0, 8),
            ("size", 0xC8, 8),
            ("fd", 0xD0, 8),
            ("bk", 0xD8, 8),
            ("fd_nextsize", 0xE0, 8),
            ("bk_nextsize", 0xE8, 8),
        ),
        guard_threshold=0xD8,
        guarded_size_field_offset=0xC8,
        guarded_size_mask=~0xF,
        guarded_size_min=0x20,
        guarded_size_max=0x520,
        guarded_bk_field_offset=0xD8,
        guarded_bk_must_be_heap=True,
    )


def test_adjacent_metadata_overwrite_reports_exact_covered_fields_and_guards():
    result = derive_adjacent_chunk_metadata_overwrite(_metadata_policy(), write_length=0xF0)
    assert result is not None
    assert result["overflow_length"] == 0x30
    assert [field["field"] for field in result["covered_fields"]] == [
        "prev_size", "size", "fd", "bk", "fd_nextsize", "bk_nextsize"
    ]
    assert result["guard_applies"] is True
    assert [constraint["kind"] for constraint in result["constraints"]] == [
        "masked_size_interval", "pointer_must_reference_heap_range"
    ]
    assert "arbitrary-address write" in result["limitations"][0]


def test_adjacent_metadata_overwrite_does_not_promote_in_bounds_write():
    assert derive_adjacent_chunk_metadata_overwrite(
        _metadata_policy(), write_length=0xC0
    ) is None


def test_adjacent_metadata_overwrite_rejects_unreviewed_overlength_write():
    assert derive_adjacent_chunk_metadata_overwrite(
        _metadata_policy(), write_length=0xF1
    ) is None


def _cet_policy():
    return ControlFlowEnforcementPolicy(
        name="reviewed CET runtime",
        shadow_stack_enforced=True,
        ibt_enforced=True,
        endbr_enforced_for_indirect_targets=True,
        runtime_engine="Intel SDE",
    )


def test_cet_blocks_saved_rip_only_candidate_without_shadow_stack_sync():
    result = assess_saved_return_control_under_policy(
        {"saved_rip_overwrite": True}, _cet_policy()
    )
    assert result["saved_rip_overwrite"] is True
    assert result["executable_control"] is False
    assert "shadow_stack_return_mismatch" in result["blockers"]


def test_cet_ibt_requires_reviewed_endbr_for_indirect_target():
    result = assess_saved_return_control_under_policy(
        {
            "saved_rip_overwrite": True,
            "shadow_stack_sync_evidence": True,
            "uses_indirect_branch": True,
            "indirect_target_endbr_evidence": False,
        },
        _cet_policy(),
    )
    assert result["executable_control"] is False
    assert "ibt_target_without_reviewed_endbr" in result["blockers"]


def test_cet_policy_can_pass_only_when_required_control_evidence_is_present():
    result = assess_saved_return_control_under_policy(
        {
            "saved_rip_overwrite": True,
            "shadow_stack_sync_evidence": True,
            "uses_indirect_branch": True,
            "indirect_target_endbr_evidence": True,
        },
        _cet_policy(),
    )
    assert result["executable_control"] is True
    assert result["blockers"] == []
