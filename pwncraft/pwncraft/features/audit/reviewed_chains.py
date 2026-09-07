"""Policy-gated exploit-chain composition for reviewed target semantics.

This module deliberately sits above primitive extraction.  It never guesses a
binary target from an address, an adjacent object from a payload length, or a
double-free from a helper name.  Each derivation requires an explicit reviewed
policy plus concrete upstream facts.

The three small engines are intentionally generic:

* additive write + reviewed target/symbol facts -> static control plan;
* reviewed adjacent-object geometry + persistent corrupted bounds -> leak /
  function-pointer overwrite capability;
* reviewed alias-sensitive helper semantics + equal call arguments ->
  conditional stale-read/double-release relation.

All results remain static/reviewed facts.  None of them claim runtime exploit
success or remote shell execution.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AdditiveControlTargetPolicy:
    name: str
    address: int
    width: int
    storage_kind: str
    target_symbol: str
    current_symbol: str
    desired_symbol: str
    current_symbol_offset: int
    desired_symbol_offset: int
    writable: bool
    fixed_address: bool
    current_value_resolved: bool
    provenance: str = "REVIEWED_BINARY_TARGET_POLICY"

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("control-target policy name must be non-empty")
        if self.address < 0 or self.width <= 0:
            raise ValueError("control-target address/width must be valid")
        if not all(
            value.strip()
            for value in (
                self.storage_kind,
                self.target_symbol,
                self.current_symbol,
                self.desired_symbol,
            )
        ):
            raise ValueError("control-target symbolic fields must be non-empty")


@dataclass(frozen=True)
class AdjacentObjectPolicy:
    name: str
    primary_object_size: int
    data_offset: int
    original_capacity: int
    dump_cap: int
    corrupted_len_lower_bound: int
    corrupted_capacity_lower_bound: int
    adjacent_field_name: str
    adjacent_field_offset_from_data: int
    adjacent_field_width: int
    clear_preserves_capacity: bool
    dump_calls_adjacent_field: bool
    provenance: str = "REVIEWED_ADJACENT_OBJECT_POLICY"

    def validate(self) -> None:
        numbers = (
            self.primary_object_size,
            self.data_offset,
            self.original_capacity,
            self.dump_cap,
            self.corrupted_len_lower_bound,
            self.corrupted_capacity_lower_bound,
            self.adjacent_field_offset_from_data,
            self.adjacent_field_width,
        )
        if not self.name.strip() or not self.adjacent_field_name.strip():
            raise ValueError("adjacent-object policy names must be non-empty")
        if any(value < 0 for value in numbers) or self.adjacent_field_width <= 0:
            raise ValueError("adjacent-object geometry must be non-negative")
        if self.data_offset >= self.primary_object_size:
            raise ValueError("data offset must lie inside the primary object")


@dataclass(frozen=True)
class AliasHelperPolicy:
    name: str
    helper: str
    alias_parameter_indexes: tuple[int, int]
    realloc_old_parameter_index: int
    realloc_may_move_and_free_old: bool
    stale_read_parameter_index: int
    explicit_free_parameter_index: int
    provenance: str = "REVIEWED_ALIAS_HELPER_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.helper.strip():
            raise ValueError("alias-helper policy names must be non-empty")
        indexes = (
            *self.alias_parameter_indexes,
            self.realloc_old_parameter_index,
            self.stale_read_parameter_index,
            self.explicit_free_parameter_index,
        )
        if any(index < 0 for index in indexes):
            raise ValueError("alias-helper parameter indexes must be non-negative")


def _primitive_is_additive(primitive: dict[str, Any]) -> bool:
    name = str(primitive.get("name") or "").lower()
    if "additive" not in name:
        return False
    evidence = primitive.get("evidence") or []
    operations = [
        item.get("operation")
        for item in evidence
        if isinstance(item, dict) and item.get("kind") == "indexed_additive_write"
    ]
    return not operations or all(operation == "add" for operation in operations)


def derive_additive_control_plan(
    primitive: dict[str, Any],
    policy: AdditiveControlTargetPolicy,
) -> dict[str, Any] | None:
    """Compose one proven additive write with reviewed binary/symbol facts.

    The plan is emitted only when every exact constraint agrees: address, width,
    writable/fixed storage, resolved current value and symbol-offset delta.
    """
    policy.validate()
    if not _primitive_is_additive(primitive):
        return None
    try:
        address = int(primitive["address"])
        width = int(primitive["width"])
        delta = int(primitive["delta"])
    except (KeyError, TypeError, ValueError):
        return None
    required_delta = policy.desired_symbol_offset - policy.current_symbol_offset
    if address != policy.address or width != policy.width or delta != required_delta:
        return None
    if not (policy.writable and policy.fixed_address and policy.current_value_resolved):
        return None
    return {
        "kind": "reviewed_additive_control_plan",
        "state": "derived_static",
        "runtime_observed": False,
        "primitive": {
            "operation": "add",
            "address": address,
            "width": width,
            "delta": delta,
        },
        "target": {
            "storage_kind": policy.storage_kind,
            "address": policy.address,
            "symbol": policy.target_symbol,
            "writable": True,
            "fixed_address": True,
        },
        "value_transition": {
            "current_symbol": policy.current_symbol,
            "desired_symbol": policy.desired_symbol,
            "current_symbol_offset": policy.current_symbol_offset,
            "desired_symbol_offset": policy.desired_symbol_offset,
            "required_delta": required_delta,
            "current_value_resolved": True,
        },
        "effect": f"{policy.target_symbol}: {policy.current_symbol} -> {policy.desired_symbol}",
        "provenance": policy.provenance,
        "limitations": [
            "this is a static control plan, not runtime exploit success",
            "the target identity and symbol offsets are reviewed policy facts",
            "the plan does not prove a subsequent trigger reaches attacker-desired behavior",
        ],
    }


def derive_adjacent_object_chain(
    policy: AdjacentObjectPolicy,
    *,
    planned_input_length: int,
) -> dict[str, Any]:
    """Derive leak/overwrite capabilities from reviewed adjacent-object geometry.

    ``corrupted_*_lower_bound`` are capabilities established by upstream target
    analysis.  The engine only performs deterministic span/bounds composition.
    """
    policy.validate()
    if planned_input_length < 0:
        raise ValueError("planned input length must be non-negative")
    field_end = policy.adjacent_field_offset_from_data + policy.adjacent_field_width
    dump_length = min(policy.corrupted_len_lower_bound, policy.dump_cap)
    leak_reaches_field = dump_length >= field_end
    capacity_survives_clear = policy.clear_preserves_capacity
    input_allowed_after_clear = bool(
        capacity_survives_clear
        and planned_input_length <= policy.corrupted_capacity_lower_bound
    )
    write_reaches_field = bool(input_allowed_after_clear and planned_input_length >= field_end)
    indirect_transfer = bool(write_reaches_field and policy.dump_calls_adjacent_field)

    facts: list[dict[str, Any]] = []
    if leak_reaches_field:
        facts.append({
            "kind": "adjacent_object_read_leak",
            "read_from": "primary.data",
            "read_length": dump_length,
            "reaches_field": policy.adjacent_field_name,
            "field_offset_from_data": policy.adjacent_field_offset_from_data,
        })
    if capacity_survives_clear:
        facts.append({
            "kind": "corrupted_capacity_persists_across_clear",
            "capacity_lower_bound": policy.corrupted_capacity_lower_bound,
            "original_capacity": policy.original_capacity,
        })
    if write_reaches_field:
        facts.append({
            "kind": "adjacent_function_pointer_overwrite",
            "field": policy.adjacent_field_name,
            "field_offset_from_data": policy.adjacent_field_offset_from_data,
            "write_length": planned_input_length,
        })
    if indirect_transfer:
        facts.append({
            "kind": "indirect_control_transfer_via_overwritten_field",
            "field": policy.adjacent_field_name,
        })

    return {
        "state": "derived_static",
        "runtime_observed": False,
        "policy": asdict(policy),
        "planned_input_length": planned_input_length,
        "computed": {
            "dump_length": dump_length,
            "adjacent_field_end": field_end,
            "leak_reaches_field": leak_reaches_field,
            "capacity_survives_clear": capacity_survives_clear,
            "input_allowed_after_clear": input_allowed_after_clear,
            "write_reaches_field": write_reaches_field,
            "indirect_control_transfer": indirect_transfer,
        },
        "facts": facts,
        "provenance": policy.provenance,
        "limitations": [
            "corruption of length/capacity is an upstream reviewed fact",
            "adjacency geometry is reviewed target evidence, not guessed from allocation names",
            "control transfer does not prove a valid context/ROP chain or shell",
        ],
    }


def _parse_call(source_call: str) -> ast.Call | None:
    try:
        node = ast.parse(source_call.strip(), mode="eval").body
    except (SyntaxError, AttributeError):
        return None
    return node if isinstance(node, ast.Call) else None


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _render(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""


def derive_alias_release_hazard(
    source_call: str,
    policy: AliasHelperPolicy,
) -> dict[str, Any] | None:
    """Derive a conditional same-identity release chain for an aliasing call.

    Equality is syntactic after AST normalization.  Different or unresolved
    expressions do not become aliases.  The double release remains conditional
    on the reviewed realloc-move/free-old precondition.
    """
    policy.validate()
    call = _parse_call(source_call)
    if call is None or _call_name(call) != policy.helper:
        return None
    max_index = max(
        *policy.alias_parameter_indexes,
        policy.realloc_old_parameter_index,
        policy.stale_read_parameter_index,
        policy.explicit_free_parameter_index,
    )
    if len(call.args) <= max_index:
        return None
    rendered = [_render(argument) for argument in call.args]
    left_index, right_index = policy.alias_parameter_indexes
    left, right = rendered[left_index], rendered[right_index]
    if not left or left != right:
        return None
    old_expr = rendered[policy.realloc_old_parameter_index]
    stale_expr = rendered[policy.stale_read_parameter_index]
    free_expr = rendered[policy.explicit_free_parameter_index]
    if not old_expr or stale_expr != old_expr or free_expr != old_expr:
        return None

    facts = [{
        "kind": "same_argument_alias",
        "expression": old_expr,
        "parameter_indexes": list(policy.alias_parameter_indexes),
    }]
    if policy.realloc_may_move_and_free_old:
        facts.extend([
            {
                "kind": "conditional_realloc_release",
                "identity": old_expr,
                "condition": "realloc moves allocation and frees old storage",
            },
            {
                "kind": "conditional_stale_read_after_realloc",
                "identity": old_expr,
                "condition": "realloc moves allocation and frees old storage",
            },
            {
                "kind": "conditional_double_release_same_identity",
                "identity": old_expr,
                "condition": "realloc moves allocation and frees old storage",
            },
        ])

    return {
        "kind": "alias_sensitive_release_chain",
        "helper": policy.helper,
        "source_call": source_call.strip(),
        "aliased_expression": old_expr,
        "conditional_double_release": policy.realloc_may_move_and_free_old,
        "state": "derived_static",
        "runtime_observed": False,
        "facts": facts,
        "provenance": policy.provenance,
        "limitations": [
            "double release is conditional on realloc moving/freeing the old allocation",
            "bin placement, consolidation and poisoning require allocator-state evidence",
            "syntactic argument equality is required; semantic aliasing is not guessed",
        ],
    }
