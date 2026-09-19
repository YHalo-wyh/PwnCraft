import json
from pathlib import Path

from pwncraft.features.audit.reviewed_tcache_metadata_target import (
    ExactTcacheMetadataTargetPolicy,
    derive_exact_tcache_metadata_target,
)
from pwncraft.features.audit.reviewed_wide_data_state import (
    ReviewedWideDataStatePolicy,
    derive_reviewed_wide_data_state,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-heapmage-9765b15f" / "expected_truth_cycle36.json"


def _metadata(entries):
    return {
        "capabilities": ["reviewed_fake_user_allocation_acquired"],
        "facts": [{"kind": "nth_allocation_returns_reviewed_user", "returned_user_address": entries}],
    }


def _libc(base):
    return {
        "runtime_observed": True,
        "capabilities": ["libc_base_derived_from_stdout_observation"],
        "facts": [{"kind": "libc_base_formula", "result": base}],
    }


def _allocation(entries, base, offset):
    return derive_exact_tcache_metadata_target(
        _metadata(entries),
        _libc(base),
        ExactTcacheMetadataTargetPolicy(
            name=f"target-{offset:x}", allocator_family="glibc", allocator_version="2.39",
            metadata_user_address=entries, tcache_entries_base=entries,
            target_entry_index=14, pointer_width=8, request_size=0xF0, chunk_size=0x100,
            target_libc_offset=offset, target_address=base + offset, alignment=16,
            tcache_count_positive_reviewed=True, entry_write_reviewed=True,
            allocation_semantics_reviewed=True,
        ),
    )


def _policy(wide, vtable):
    return ReviewedWideDataStatePolicy(
        name="heapmage-wide-data-state",
        allocator_family="glibc", allocator_version="2.39",
        wide_data_address=wide, wide_vtable_address=vtable,
        field_writes_reviewed=True,
    )


def test_cycle36_two_exact_targets_prepare_reviewed_wide_data_state_only():
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    rel = truth["relative_policy"]
    heap = 0x555550000000
    entries = heap + rel["metadata_user_heap_offset"]
    libc = 0x7F4567000000
    wide = libc + rel["wide_data_libc_offset"]
    vtable = libc + rel["wide_vtable_libc_offset"]
    wide_alloc = _allocation(entries, libc, rel["wide_data_libc_offset"])
    vtable_alloc = _allocation(entries, libc, rel["wide_vtable_libc_offset"])
    assert wide_alloc is not None and vtable_alloc is not None

    result = derive_reviewed_wide_data_state(
        wide_alloc, vtable_alloc, _policy(wide, vtable),
        field_writes=(
            {"offset": 0x18, "value": 0, "width": 8},
            {"offset": 0x20, "value": 1, "width": 8},
            {"offset": 0x30, "value": 0, "width": 8},
            {"offset": 0xE0, "value": vtable, "width": 8},
        ),
    )
    assert result is not None
    assert result["facts"][1]["wide_vtable_address"] == vtable
    assert result["capabilities"] == ["reviewed_wide_data_state_prepared"]
    assert "system" not in " ".join(result["capabilities"]).lower()


def test_cycle36_wrong_wide_vtable_pointer_stays_unknown():
    entries = 0x555550000090
    libc = 0x7F4567000000
    wide, vtable = libc + 0x204800, libc + 0x204900
    assert derive_reviewed_wide_data_state(
        _allocation(entries, libc, 0x204800),
        _allocation(entries, libc, 0x204900),
        _policy(wide, vtable),
        field_writes=(
            {"offset": 0x18, "value": 0, "width": 8},
            {"offset": 0x20, "value": 1, "width": 8},
            {"offset": 0x30, "value": 0, "width": 8},
            {"offset": 0xE0, "value": vtable + 0x100, "width": 8},
        ),
    ) is None


def test_cycle36_missing_exact_second_target_stays_unknown():
    entries = 0x555550000090
    libc = 0x7F4567000000
    wide, vtable = libc + 0x204800, libc + 0x204900
    assert derive_reviewed_wide_data_state(
        _allocation(entries, libc, 0x204800),
        {"capabilities": [], "facts": []},
        _policy(wide, vtable),
        field_writes=(
            {"offset": 0x18, "value": 0, "width": 8},
            {"offset": 0x20, "value": 1, "width": 8},
            {"offset": 0x30, "value": 0, "width": 8},
            {"offset": 0xE0, "value": vtable, "width": 8},
        ),
    ) is None
