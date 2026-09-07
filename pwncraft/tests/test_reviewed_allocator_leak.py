from pwncraft.features.audit.reviewed_allocator_leak import (
    StdoutLow16CandidatePolicy,
    UnsortedTcacheLibcSeedPolicy,
    derive_libc_base_from_stdout_observation,
    derive_stdout_low16_candidate,
    derive_unsorted_tcache_libc_seed,
)


def _upstream(base):
    return {
        "capabilities": ["reviewed_fake_user_allocation_acquired"],
        "facts": [{"kind": "nth_allocation_returns_reviewed_user", "returned_user_address": base}],
    }


def test_unsorted_seed_requires_full_tcache_and_exact_entry_overlap():
    base = 0x555550000090
    fake_user = base + 14 * 8
    policy = UnsortedTcacheLibcSeedPolicy(
        name="reviewed unsorted pointer seed",
        allocator_family="glibc",
        allocator_version="2.39",
        acquired_metadata_user_address=base,
        tcache_entries_base=base,
        fake_user_address=fake_user,
        fake_chunk_header_address=fake_user - 0x10,
        chunk_header_size=0x10,
        fake_chunk_size=0x100,
        target_entry_index=14,
        pointer_width=8,
        tcache_count_before_free=7,
        tcache_capacity=7,
        unsorted_insert_reviewed=True,
        libc_pointer_write_reviewed=True,
    )
    result = derive_unsorted_tcache_libc_seed(_upstream(base), policy)
    assert result is not None
    assert result["facts"][-1]["entry_index"] == 14
    assert result["capabilities"] == ["libc_pointer_seeded_in_tcache_metadata"]

    not_full = UnsortedTcacheLibcSeedPolicy(**{**policy.__dict__, "tcache_count_before_free": 6})
    assert derive_unsorted_tcache_libc_seed(_upstream(base), not_full) is None


def test_stdout_partial_retarget_is_only_a_finite_candidate():
    upstream = {"capabilities": ["libc_pointer_seeded_in_tcache_metadata"]}
    policy = StdoutLow16CandidatePolicy(
        name="stdout candidate",
        tcache_entries_base=0x555550000090,
        target_entry_index=14,
        pointer_width=8,
        libc_low_nibble_guess=3,
        stdout_symbol_offset=0x2045C0,
    )
    result = derive_stdout_low16_candidate(upstream, policy)
    assert result is not None
    assert result["facts"][1]["candidate_count"] == 16
    assert result["capabilities"] == ["stdout_partial_retarget_candidate"]
    assert result["runtime_observed"] is False


def test_libc_base_requires_runtime_pointer_observation_and_explicit_formula():
    stdout_off = 0x2045C0
    field_off = 0x84
    base = 0x7F1234000000
    leak = base + stdout_off + field_off
    result = derive_libc_base_from_stdout_observation(
        leak,
        stdout_symbol_offset=stdout_off,
        observed_field_offset=field_off,
    )
    assert result is not None
    assert result["facts"][1]["result"] == base
    assert result["runtime_observed"] is True
    assert derive_libc_base_from_stdout_observation(
        0x41414141,
        stdout_symbol_offset=stdout_off,
        observed_field_offset=field_off,
    ) is None
