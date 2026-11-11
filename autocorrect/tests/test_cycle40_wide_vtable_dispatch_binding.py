from pwncraft.features.audit.reviewed_wide_vtable_dispatch import (
    ReviewedWideVtableDispatchPolicy,
    derive_reviewed_wide_vtable_dispatch,
)


WIDE_VTABLE = 0x7F4567204900
SYSTEM = 0x7F4567052290


def _wide_data_state(vtable=WIDE_VTABLE):
    return {
        "capabilities": ["reviewed_wide_data_state_prepared"],
        "facts": [{
            "kind": "reviewed_wide_data_vtable_pointer",
            "wide_vtable_address": vtable,
        }],
    }


def _allocation(address=WIDE_VTABLE):
    return {
        "capabilities": ["reviewed_exact_tcache_allocation_target"],
        "facts": [{
            "kind": "reviewed_next_allocation_returns_exact_target",
            "returned_user_address": address,
        }],
    }


def _symbols(system=SYSTEM):
    return {
        "capabilities": ["reviewed_runtime_libc_symbols_resolved"],
        "bindings": {"dispatch": system},
    }


def _policy(reviewed=True):
    return ReviewedWideVtableDispatchPolicy(
        name="heapmage-wide-doallocate",
        wide_vtable_address=WIDE_VTABLE,
        dispatch_role="dispatch",
        dispatch_slot_offset=0x68,
        pointer_width=8,
        slot_write_reviewed=reviewed,
    )


def test_cycle40_exact_wide_vtable_slot_binds_runtime_dispatch_symbol():
    result = derive_reviewed_wide_vtable_dispatch(
        _wide_data_state(),
        _allocation(),
        _symbols(),
        _policy(),
        slot_write={"offset": 0x68, "value": SYSTEM, "width": 8},
    )
    assert result is not None
    assert result["facts"][1]["slot_address"] == WIDE_VTABLE + 0x68
    assert result["facts"][1]["runtime_target"] == SYSTEM
    assert result["capabilities"] == ["reviewed_wide_vtable_dispatch_target"]


def test_cycle40_wrong_region_or_slot_value_stays_unknown():
    assert derive_reviewed_wide_vtable_dispatch(
        _wide_data_state(WIDE_VTABLE + 0x100),
        _allocation(),
        _symbols(),
        _policy(),
        slot_write={"offset": 0x68, "value": SYSTEM, "width": 8},
    ) is None

    assert derive_reviewed_wide_vtable_dispatch(
        _wide_data_state(),
        _allocation(),
        _symbols(),
        _policy(),
        slot_write={"offset": 0x68, "value": SYSTEM + 1, "width": 8},
    ) is None


def test_cycle40_unreviewed_slot_or_missing_symbol_binding_stays_unknown():
    assert derive_reviewed_wide_vtable_dispatch(
        _wide_data_state(),
        _allocation(),
        _symbols(),
        _policy(reviewed=False),
        slot_write={"offset": 0x68, "value": SYSTEM, "width": 8},
    ) is None

    assert derive_reviewed_wide_vtable_dispatch(
        _wide_data_state(),
        _allocation(),
        {"capabilities": [], "bindings": {}},
        _policy(),
        slot_write={"offset": 0x68, "value": SYSTEM, "width": 8},
    ) is None


def test_cycle40_dispatch_binding_does_not_promote_runtime_invocation():
    result = derive_reviewed_wide_vtable_dispatch(
        _wide_data_state(),
        _allocation(),
        _symbols(),
        _policy(),
        slot_write={"offset": 0x68, "value": SYSTEM, "width": 8},
    )
    assert result is not None
    flattened = " ".join(result["capabilities"] + result["limitations"]).lower()
    assert "runtime exploit success" in flattened
    assert "shell" in flattened
