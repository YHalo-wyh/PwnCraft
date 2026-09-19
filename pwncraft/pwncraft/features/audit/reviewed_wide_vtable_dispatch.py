"""Reviewed wide-vtable dispatch-slot binding.

This layer joins three already-proven facts: a prepared wide-data object that
points at a reviewed wide-vtable region, the exact allocation identity of that
wide-vtable region, and an artifact-anchored runtime libc symbol binding.  It
then verifies one explicit slot write.

The result is only a dispatch-target binding.  It does not prove a FILE object
reaches the wide path or that the slot is invoked at runtime.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ReviewedWideVtableDispatchPolicy:
    name: str
    wide_vtable_address: int
    dispatch_role: str
    dispatch_slot_offset: int
    pointer_width: int = 8
    slot_write_reviewed: bool = False
    provenance: str = "REVIEWED_WIDE_VTABLE_DISPATCH_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.dispatch_role.strip():
            raise ValueError("wide-vtable dispatch policy identity must be complete")
        if min(self.wide_vtable_address, self.dispatch_slot_offset) < 0 or self.pointer_width <= 0:
            raise ValueError("wide-vtable dispatch geometry must be valid")


def _wide_data_points_to(upstream: dict[str, Any]) -> int | None:
    if "reviewed_wide_data_state_prepared" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "reviewed_wide_data_vtable_pointer":
            value = fact.get("wide_vtable_address")
            return int(value) if isinstance(value, int) else None
    return None


def _exact_allocation_return(upstream: dict[str, Any]) -> int | None:
    if "reviewed_exact_tcache_allocation_target" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "reviewed_next_allocation_returns_exact_target":
            value = fact.get("returned_user_address")
            return int(value) if isinstance(value, int) else None
    return None


def _symbol_binding(upstream: dict[str, Any], role: str) -> int | None:
    if "reviewed_runtime_libc_symbols_resolved" not in (upstream.get("capabilities") or []):
        return None
    bindings = upstream.get("bindings")
    if not isinstance(bindings, dict):
        return None
    value = bindings.get(role)
    return int(value) if isinstance(value, int) else None


def derive_reviewed_wide_vtable_dispatch(
    wide_data_state: dict[str, Any],
    wide_vtable_allocation: dict[str, Any],
    libc_symbols: dict[str, Any],
    policy: ReviewedWideVtableDispatchPolicy,
    *,
    slot_write: dict[str, int],
) -> dict[str, Any] | None:
    """Bind one reviewed wide-vtable slot to one exact runtime symbol."""
    policy.validate()
    if _wide_data_points_to(wide_data_state) != policy.wide_vtable_address:
        return None
    if _exact_allocation_return(wide_vtable_allocation) != policy.wide_vtable_address:
        return None
    dispatch_target = _symbol_binding(libc_symbols, policy.dispatch_role)
    if dispatch_target is None or not policy.slot_write_reviewed:
        return None
    if not isinstance(slot_write, dict):
        return None
    offset = slot_write.get("offset")
    value = slot_write.get("value")
    width = slot_write.get("width", policy.pointer_width)
    if (
        offset != policy.dispatch_slot_offset
        or value != dispatch_target
        or width != policy.pointer_width
    ):
        return None

    slot_address = policy.wide_vtable_address + policy.dispatch_slot_offset
    return {
        "kind": "reviewed_wide_vtable_dispatch_binding",
        "state": "derived_runtime_bound",
        "runtime_observed": True,
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "reviewed_wide_vtable_region_identity",
                "wide_vtable_address": policy.wide_vtable_address,
            },
            {
                "kind": "reviewed_wide_vtable_dispatch_slot_write",
                "slot_offset": policy.dispatch_slot_offset,
                "slot_address": slot_address,
                "width": policy.pointer_width,
                "runtime_target": dispatch_target,
                "target_role": policy.dispatch_role,
            },
        ],
        "capabilities": ["reviewed_wide_vtable_dispatch_target"],
        "provenance": policy.provenance,
        "limitations": [
            "this proves the reviewed slot value, not that a FILE/stdio path invokes the slot",
            "the dispatch target's symbol identity was resolved upstream from an exact libc artifact",
            "no command execution, shell, flag retrieval or runtime exploit success is inferred",
        ],
    }
