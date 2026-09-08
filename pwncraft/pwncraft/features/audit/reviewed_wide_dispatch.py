"""Reviewed stdio wide-vtable dispatch composition.

This layer starts only after a reviewed FILE object is already bound to stdout and
a reviewed stdio trigger is reachable.  It resolves one explicitly reviewed
wide-vtable slot to one exact target address.  It does not infer House-of-Apple,
setcontext frame semantics, stack pivoting, ROP/ORW execution, or exploit success.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ReviewedWideDispatchPolicy:
    name: str
    allocator_family: str
    allocator_version: str
    file_object_address: int
    wide_data_address: int
    file_vtable_address: int
    wide_vtable_address: int
    dispatch_target_address: int
    wide_data_field_offset: int = 0xA0
    file_vtable_field_offset: int = 0xD8
    wide_vtable_pointer_offset: int = 0xE0
    dispatch_slot_offset: int = 0x68
    pointer_width: int = 8
    file_vtable_semantics_reviewed: bool = False
    wide_dispatch_semantics_reviewed: bool = False
    target_identity_reviewed: bool = False
    target_symbol: str = ""
    provenance: str = "REVIEWED_WIDE_STDIO_DISPATCH_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("wide-dispatch policy identity must be complete")
        if not self.target_symbol.strip():
            raise ValueError("wide-dispatch target symbol must be explicit")
        numeric = (
            self.file_object_address,
            self.wide_data_address,
            self.file_vtable_address,
            self.wide_vtable_address,
            self.dispatch_target_address,
            self.wide_data_field_offset,
            self.file_vtable_field_offset,
            self.wide_vtable_pointer_offset,
            self.dispatch_slot_offset,
            self.pointer_width,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("wide-dispatch addresses/offsets must be non-negative")
        if self.pointer_width <= 0:
            raise ValueError("wide-dispatch pointer width must be positive")


def _reviewed_file_fields(upstream: dict[str, Any]) -> dict[str, dict[str, Any]] | None:
    capabilities = set(upstream.get("capabilities") or [])
    if not {
        "stdout_rebound_to_reviewed_file_object",
        "reviewed_stdio_path_reachable",
    }.issubset(capabilities):
        return None
    for fact in upstream.get("facts") or []:
        if not isinstance(fact, dict) or fact.get("kind") != "reviewed_file_field_state":
            continue
        fields = fact.get("fields") or []
        by_role = {
            str(item.get("role")): item
            for item in fields
            if isinstance(item, dict) and str(item.get("role") or "")
        }
        return by_role
    return None


def derive_reviewed_wide_dispatch(
    upstream: dict[str, Any],
    policy: ReviewedWideDispatchPolicy,
    *,
    wide_writes: tuple[dict[str, int], ...],
) -> dict[str, Any] | None:
    """Resolve one reviewed wide-vtable dispatch slot to one exact target.

    ``wide_writes`` is address/value evidence for the separately allocated wide
    region.  The rule requires exact FILE->_wide_data and FILE->vtable bindings,
    an exact wide-data->_wide_vtable pointer, and the exact reviewed dispatch slot
    containing the reviewed target.  No context-frame semantics are inferred.
    """
    policy.validate()
    fields = _reviewed_file_fields(upstream)
    if fields is None:
        return None

    wide_field = fields.get("wide_data")
    file_vtable_field = fields.get("vtable")
    if wide_field is None or file_vtable_field is None:
        return None
    if wide_field.get("offset") != policy.wide_data_field_offset:
        return None
    if wide_field.get("value") != policy.wide_data_address:
        return None
    if file_vtable_field.get("offset") != policy.file_vtable_field_offset:
        return None
    if file_vtable_field.get("value") != policy.file_vtable_address:
        return None

    if not (
        policy.file_vtable_semantics_reviewed
        and policy.wide_dispatch_semantics_reviewed
        and policy.target_identity_reviewed
    ):
        return None

    writes: dict[int, int] = {}
    for item in wide_writes:
        if not isinstance(item, dict):
            return None
        address = item.get("address")
        value = item.get("value")
        width = item.get("width", policy.pointer_width)
        if not isinstance(address, int) or not isinstance(value, int) or not isinstance(width, int):
            return None
        if address < 0 or value < 0 or width != policy.pointer_width:
            return None
        if address in writes:
            return None
        writes[address] = value

    wide_vtable_pointer_address = policy.wide_data_address + policy.wide_vtable_pointer_offset
    dispatch_slot_address = policy.wide_vtable_address + policy.dispatch_slot_offset
    if writes.get(wide_vtable_pointer_address) != policy.wide_vtable_address:
        return None
    if writes.get(dispatch_slot_address) != policy.dispatch_target_address:
        return None

    return {
        "kind": "reviewed_wide_stdio_dispatch",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "reviewed_file_wide_data_binding",
                "file_object_address": policy.file_object_address,
                "field_address": policy.file_object_address + policy.wide_data_field_offset,
                "wide_data_address": policy.wide_data_address,
            },
            {
                "kind": "reviewed_file_vtable_binding",
                "file_object_address": policy.file_object_address,
                "field_address": policy.file_object_address + policy.file_vtable_field_offset,
                "file_vtable_address": policy.file_vtable_address,
            },
            {
                "kind": "reviewed_wide_vtable_binding",
                "wide_data_address": policy.wide_data_address,
                "field_address": wide_vtable_pointer_address,
                "wide_vtable_address": policy.wide_vtable_address,
            },
            {
                "kind": "reviewed_wide_dispatch_target",
                "slot_address": dispatch_slot_address,
                "slot_offset": policy.dispatch_slot_offset,
                "target_address": policy.dispatch_target_address,
                "target_symbol": policy.target_symbol,
            },
        ],
        "capabilities": [
            "reviewed_wide_vtable_dispatch_target",
            "reviewed_stdio_dispatch_target_reachable",
        ],
        "provenance": policy.provenance,
        "limitations": [
            "the exact dispatch target is proven only under the reviewed FILE/wide-vtable policy",
            "dispatch to a setcontext symbol does not prove which registers or stack pointer are restored",
            "no setcontext frame validity, stack pivot, ROP/ORW execution, shell or flag retrieval is inferred here",
        ],
    }
