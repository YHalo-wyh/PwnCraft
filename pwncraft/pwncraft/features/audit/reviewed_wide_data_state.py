"""Reviewed wide-data state composition for stdio exploitation paths.

This layer consumes two already-proven exact allocation targets and explicit
wide-data field writes.  It proves only the prepared wide-data structure and its
pointer to a separately allocated wide-vtable region.  Dispatch-slot contents,
FILE binding and control transfer remain separate layers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ReviewedWideDataStatePolicy:
    name: str
    allocator_family: str
    allocator_version: str
    wide_data_address: int
    wide_vtable_address: int
    write_base_offset: int = 0x18
    write_ptr_offset: int = 0x20
    buf_base_offset: int = 0x30
    wide_vtable_pointer_offset: int = 0xE0
    pointer_width: int = 8
    field_writes_reviewed: bool = False
    provenance: str = "REVIEWED_WIDE_DATA_STATE_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("wide-data policy identity must be complete")
        values = (
            self.wide_data_address,
            self.wide_vtable_address,
            self.write_base_offset,
            self.write_ptr_offset,
            self.buf_base_offset,
            self.wide_vtable_pointer_offset,
            self.pointer_width,
        )
        if any(value < 0 for value in values):
            raise ValueError("wide-data geometry must be non-negative")
        if self.pointer_width <= 0:
            raise ValueError("wide-data pointer width must be positive")


def _exact_return(upstream: dict[str, Any]) -> int | None:
    if "reviewed_exact_tcache_allocation_target" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "reviewed_next_allocation_returns_exact_target":
            value = fact.get("returned_user_address")
            return int(value) if isinstance(value, int) else None
    return None


def derive_reviewed_wide_data_state(
    wide_data_allocation: dict[str, Any],
    wide_vtable_allocation: dict[str, Any],
    policy: ReviewedWideDataStatePolicy,
    *,
    field_writes: tuple[dict[str, int], ...],
) -> dict[str, Any] | None:
    """Prove the reviewed wide-data fields and wide-vtable pointer binding."""
    policy.validate()
    if _exact_return(wide_data_allocation) != policy.wide_data_address:
        return None
    if _exact_return(wide_vtable_allocation) != policy.wide_vtable_address:
        return None
    if not policy.field_writes_reviewed:
        return None

    writes: dict[int, int] = {}
    for item in field_writes:
        if not isinstance(item, dict):
            return None
        offset = item.get("offset")
        value = item.get("value")
        width = item.get("width", policy.pointer_width)
        if not isinstance(offset, int) or not isinstance(value, int) or not isinstance(width, int):
            return None
        if offset < 0 or value < 0 or width <= 0 or offset in writes:
            return None
        if width != policy.pointer_width:
            return None
        writes[offset] = value

    required = {
        policy.write_base_offset: 0,
        policy.write_ptr_offset: 1,
        policy.buf_base_offset: 0,
        policy.wide_vtable_pointer_offset: policy.wide_vtable_address,
    }
    if any(writes.get(offset) != value for offset, value in required.items()):
        return None

    return {
        "kind": "reviewed_wide_data_state",
        "state": "derived_runtime_bound",
        "runtime_observed": True,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "reviewed_wide_data_write_window",
                "wide_data_address": policy.wide_data_address,
                "write_base": 0,
                "write_ptr": 1,
                "buf_base": 0,
            },
            {
                "kind": "reviewed_wide_data_vtable_pointer",
                "field_address": policy.wide_data_address + policy.wide_vtable_pointer_offset,
                "wide_vtable_address": policy.wide_vtable_address,
            },
            {
                "kind": "reviewed_wide_data_field_writes",
                "fields": [dict(item) for item in field_writes],
            },
        ],
        "capabilities": ["reviewed_wide_data_state_prepared"],
        "provenance": policy.provenance,
        "limitations": [
            "this proves only the reviewed wide-data object and its wide-vtable pointer",
            "the contents of the wide-vtable dispatch slot are not proven by this layer",
            "no fake FILE binding, system dispatch, command execution, shell or flag retrieval is inferred",
        ],
    }
