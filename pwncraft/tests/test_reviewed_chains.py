from dataclasses import replace

from pwncraft.features.audit.reviewed_chains import (
    AdditiveControlTargetPolicy,
    AdjacentObjectPolicy,
    AliasHelperPolicy,
    derive_additive_control_plan,
    derive_adjacent_object_chain,
    derive_alias_release_hazard,
)


def _write(*, address=0x404018, delta=-205200, width=8):
    return {
        "name": "constrained additive 64-bit write",
        "domain": "memory_write",
        "state": "derived_static",
        "address": address,
        "width": width,
        "delta": delta,
        "evidence": [{"kind": "indexed_additive_write", "operation": "add"}],
    }


def _control_policy(**changes):
    policy = AdditiveControlTargetPolicy(
        name="reviewed-relocation-target",
        address=0x404018,
        width=8,
        storage_kind="got_relocation",
        target_symbol="puts@GOT",
        current_symbol="puts",
        desired_symbol="system",
        current_symbol_offset=0x77980,
        desired_symbol_offset=0x457F0,
        writable=True,
        fixed_address=True,
        current_value_resolved=True,
    )
    return replace(policy, **changes)


def test_additive_write_plus_exact_reviewed_target_yields_control_plan() -> None:
    plan = derive_additive_control_plan(_write(), _control_policy())
    assert plan is not None
    assert plan["primitive"] == {
        "operation": "add", "address": 0x404018, "width": 8, "delta": -205200
    }
    assert plan["target"]["symbol"] == "puts@GOT"
    assert plan["value_transition"]["current_symbol"] == "puts"
    assert plan["value_transition"]["desired_symbol"] == "system"
    assert plan["value_transition"]["required_delta"] == -205200
    assert plan["state"] == "derived_static"
    assert plan["runtime_observed"] is False


def test_control_plan_rejects_address_delta_or_target_precondition_mismatch() -> None:
    assert derive_additive_control_plan(_write(address=0x404020), _control_policy()) is None
    assert derive_additive_control_plan(_write(delta=-1), _control_policy()) is None
    assert derive_additive_control_plan(_write(), _control_policy(writable=False)) is None
    assert derive_additive_control_plan(_write(), _control_policy(fixed_address=False)) is None
    assert derive_additive_control_plan(_write(), _control_policy(current_value_resolved=False)) is None


def _adjacent_policy(**changes):
    policy = AdjacentObjectPolicy(
        name="reviewed-page-route-layout",
        primary_object_size=0x800,
        data_offset=0x20,
        original_capacity=0x7E0,
        dump_cap=0x1000,
        corrupted_len_lower_bound=0x1000,
        corrupted_capacity_lower_bound=0x900,
        adjacent_field_name="route.sink",
        adjacent_field_offset_from_data=0x830,
        adjacent_field_width=8,
        clear_preserves_capacity=True,
        dump_calls_adjacent_field=True,
    )
    return replace(policy, **changes)


def test_adjacent_object_geometry_derives_leak_overwrite_and_indirect_transfer() -> None:
    chain = derive_adjacent_object_chain(_adjacent_policy(), planned_input_length=0x900)
    computed = chain["computed"]
    assert computed["leak_reaches_field"] is True
    assert computed["input_allowed_after_clear"] is True
    assert computed["write_reaches_field"] is True
    assert computed["indirect_control_transfer"] is True
    kinds = {item["kind"] for item in chain["facts"]}
    assert "adjacent_object_read_leak" in kinds
    assert "corrupted_capacity_persists_across_clear" in kinds
    assert "adjacent_function_pointer_overwrite" in kinds
    assert "indirect_control_transfer_via_overwritten_field" in kinds


def test_adjacent_chain_stops_when_clear_repairs_capacity_or_payload_is_short() -> None:
    repaired = derive_adjacent_object_chain(
        _adjacent_policy(clear_preserves_capacity=False), planned_input_length=0x900
    )
    assert repaired["computed"]["write_reaches_field"] is False
    assert repaired["computed"]["indirect_control_transfer"] is False

    short = derive_adjacent_object_chain(_adjacent_policy(), planned_input_length=0x800)
    assert short["computed"]["input_allowed_after_clear"] is True
    assert short["computed"]["write_reaches_field"] is False


def _alias_policy(**changes):
    policy = AliasHelperPolicy(
        name="reviewed-realloc-concat-free-merge",
        helper="merge",
        alias_parameter_indexes=(0, 1),
        realloc_old_parameter_index=0,
        realloc_may_move_and_free_old=True,
        stale_read_parameter_index=1,
        explicit_free_parameter_index=1,
    )
    return replace(policy, **changes)


def test_equal_merge_arguments_derive_conditional_stale_read_and_double_release() -> None:
    relation = derive_alias_release_hazard("merge(0, 0)", _alias_policy())
    assert relation is not None
    assert relation["aliased_expression"] == "0"
    assert relation["conditional_double_release"] is True
    kinds = {item["kind"] for item in relation["facts"]}
    assert "same_argument_alias" in kinds
    assert "conditional_realloc_release" in kinds
    assert "conditional_stale_read_after_realloc" in kinds
    assert "conditional_double_release_same_identity" in kinds


def test_alias_release_requires_equal_arguments_and_reviewed_realloc_release() -> None:
    assert derive_alias_release_hazard("merge(0, 1)", _alias_policy()) is None
    relation = derive_alias_release_hazard(
        "merge(idx, idx)", _alias_policy(realloc_may_move_and_free_old=False)
    )
    assert relation is not None
    assert relation["conditional_double_release"] is False
    assert {item["kind"] for item in relation["facts"]} == {"same_argument_alias"}
    assert derive_alias_release_hazard("combine(0, 0)", _alias_policy()) is None
