"""Reviewed allocator/control-flow composition helpers.

The engines in this module are deliberately policy-gated.  They compose facts
that were already established from source/binary/runtime material; they do not
recognize challenge names, infer glibc from a House-of-* label, or promote a
saved return-address overwrite to executable control under CET without the
required evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ResizedDoubleReleasePolicy:
    """Reviewed allocator state for one alias-sensitive two-release sequence."""

    name: str
    allocator_family: str
    allocator_version: str
    initial_chunk_size: int
    adjacent_free_chunk_size: int
    first_sizeclass_cache_count: int
    first_sizeclass_cache_capacity: int
    first_cache_bypass_destination: str
    forward_consolidation_reviewed: bool
    consolidated_chunk_size: int
    second_sizeclass_cache_count: int
    second_sizeclass_cache_capacity: int
    second_cache_destination: str
    provenance: str = "REVIEWED_ALLOCATOR_STATE_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("allocator policy identity must be complete")
        if self.initial_chunk_size <= 0 or self.adjacent_free_chunk_size < 0:
            raise ValueError("chunk sizes must be valid")
        if self.first_sizeclass_cache_capacity <= 0 or self.second_sizeclass_cache_capacity <= 0:
            raise ValueError("cache capacities must be positive")
        if not 0 <= self.first_sizeclass_cache_count <= self.first_sizeclass_cache_capacity:
            raise ValueError("first cache count outside capacity")
        if not 0 <= self.second_sizeclass_cache_count <= self.second_sizeclass_cache_capacity:
            raise ValueError("second cache count outside capacity")
        if not self.first_cache_bypass_destination.strip() or not self.second_cache_destination.strip():
            raise ValueError("allocator destinations must be explicit")
        if self.consolidated_chunk_size != self.initial_chunk_size + self.adjacent_free_chunk_size:
            raise ValueError("consolidated size must equal the reviewed adjacent-span sum")


@dataclass(frozen=True)
class AdjacentChunkMetadataPolicy:
    """Reviewed source/runtime geometry for a bounded adjacent-chunk overwrite."""

    name: str
    allocator_family: str
    allocator_version: str
    user_capacity: int
    maximum_write_length: int
    metadata_fields: tuple[tuple[str, int, int], ...]
    guard_threshold: int
    guarded_size_field_offset: int
    guarded_size_mask: int
    guarded_size_min: int
    guarded_size_max: int
    guarded_bk_field_offset: int
    guarded_bk_must_be_heap: bool
    provenance: str = "REVIEWED_ADJACENT_CHUNK_METADATA_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("metadata policy identity must be complete")
        if self.user_capacity <= 0 or self.maximum_write_length < self.user_capacity:
            raise ValueError("write geometry is invalid")
        if self.guard_threshold < 0 or self.guarded_size_field_offset < 0 or self.guarded_bk_field_offset < 0:
            raise ValueError("guard offsets must be non-negative")
        if self.guarded_size_min < 0 or self.guarded_size_max < self.guarded_size_min:
            raise ValueError("guarded size interval is invalid")
        seen: set[str] = set()
        for field_name, offset, width in self.metadata_fields:
            if not field_name or field_name in seen or offset < 0 or width <= 0:
                raise ValueError("metadata fields must have unique names and valid spans")
            seen.add(field_name)


@dataclass(frozen=True)
class ControlFlowEnforcementPolicy:
    """Reviewed runtime control-flow enforcement facts."""

    name: str
    shadow_stack_enforced: bool
    ibt_enforced: bool
    endbr_enforced_for_indirect_targets: bool
    runtime_engine: str
    provenance: str = "REVIEWED_CONTROL_FLOW_ENFORCEMENT_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.runtime_engine.strip():
            raise ValueError("control-flow policy identity must be complete")
        if self.endbr_enforced_for_indirect_targets and not self.ibt_enforced:
            raise ValueError("ENDBR enforcement requires IBT enforcement")


def _has_conditional_double_release(alias_chain: dict[str, Any]) -> bool:
    if not alias_chain.get("conditional_double_release"):
        return False
    return any(
        isinstance(fact, dict) and fact.get("kind") == "conditional_double_release_same_identity"
        for fact in alias_chain.get("facts") or []
    )


def derive_resized_double_release_bins(
    alias_chain: dict[str, Any],
    policy: ResizedDoubleReleasePolicy,
) -> dict[str, Any] | None:
    """Compose an alias double-release relation with reviewed allocator state.

    No bin transition is emitted unless the first size-class cache is reviewed
    full, the forward consolidation is reviewed, and the second size-class
    cache is reviewed to have capacity.
    """
    policy.validate()
    if not _has_conditional_double_release(alias_chain):
        return None

    first_cache_full = (
        policy.first_sizeclass_cache_count == policy.first_sizeclass_cache_capacity
    )
    second_cache_has_room = (
        policy.second_sizeclass_cache_count < policy.second_sizeclass_cache_capacity
    )
    if not (first_cache_full and policy.forward_consolidation_reviewed and second_cache_has_room):
        return None

    identity = str(alias_chain.get("aliased_expression") or "old")
    facts = [
        {
            "kind": "first_release_cache_bypass",
            "identity": identity,
            "chunk_size": policy.initial_chunk_size,
            "cache_count": policy.first_sizeclass_cache_count,
            "cache_capacity": policy.first_sizeclass_cache_capacity,
            "destination": policy.first_cache_bypass_destination,
        },
        {
            "kind": "forward_consolidation_changes_chunk_size",
            "identity": identity,
            "old_chunk_size": policy.initial_chunk_size,
            "adjacent_free_chunk_size": policy.adjacent_free_chunk_size,
            "new_chunk_size": policy.consolidated_chunk_size,
        },
        {
            "kind": "second_release_uses_resized_header",
            "identity": identity,
            "chunk_size": policy.consolidated_chunk_size,
            "cache_count": policy.second_sizeclass_cache_count,
            "cache_capacity": policy.second_sizeclass_cache_capacity,
            "destination": policy.second_cache_destination,
        },
        {
            "kind": "same_identity_cross_bin_membership",
            "identity": identity,
            "first_destination": policy.first_cache_bypass_destination,
            "second_destination": policy.second_cache_destination,
        },
    ]
    return {
        "kind": "reviewed_resized_double_release_bins",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {
            "family": policy.allocator_family,
            "version": policy.allocator_version,
        },
        "identity": identity,
        "policy": asdict(policy),
        "facts": facts,
        "capabilities": ["same_identity_cross_bin_membership"],
        "provenance": policy.provenance,
        "limitations": [
            "the realloc move/free-old condition remains inherited from the alias-chain fact",
            "cross-bin membership is not itself tcache poisoning or an arbitrary allocation",
            "later freelist corruption requires separate pointer/write and allocator-state evidence",
        ],
    }


def derive_adjacent_chunk_metadata_overwrite(
    policy: AdjacentChunkMetadataPolicy,
    *,
    write_length: int,
) -> dict[str, Any] | None:
    """Describe exactly which reviewed adjacent metadata fields are writable."""
    policy.validate()
    if write_length < 0 or write_length > policy.maximum_write_length:
        return None
    if write_length <= policy.user_capacity:
        return None

    covered: list[dict[str, Any]] = []
    for field_name, offset, width in policy.metadata_fields:
        if offset + width <= write_length:
            covered.append({"field": field_name, "offset": offset, "width": width})

    if not covered:
        return None
    guard_applies = write_length > policy.guard_threshold
    constraints: list[dict[str, Any]] = []
    if guard_applies:
        constraints.append({
            "kind": "masked_size_interval",
            "field_offset": policy.guarded_size_field_offset,
            "mask": policy.guarded_size_mask,
            "minimum": policy.guarded_size_min,
            "maximum": policy.guarded_size_max,
        })
        if policy.guarded_bk_must_be_heap:
            constraints.append({
                "kind": "pointer_must_reference_heap_range",
                "field_offset": policy.guarded_bk_field_offset,
            })

    return {
        "kind": "reviewed_adjacent_chunk_metadata_overwrite",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {
            "family": policy.allocator_family,
            "version": policy.allocator_version,
        },
        "write_length": write_length,
        "user_capacity": policy.user_capacity,
        "overflow_length": write_length - policy.user_capacity,
        "covered_fields": covered,
        "guard_applies": guard_applies,
        "constraints": constraints,
        "provenance": policy.provenance,
        "limitations": [
            "this is a bounded adjacent metadata overwrite, not an arbitrary-address write",
            "bin consequences are not inferred without a separate allocator-state composition",
            "allocator family/version are reviewed policy facts and must not be guessed from technique names",
        ],
    }


def assess_saved_return_control_under_policy(
    candidate: dict[str, Any],
    policy: ControlFlowEnforcementPolicy,
) -> dict[str, Any]:
    """Gate a conventional return-address-control candidate through CET facts."""
    policy.validate()
    saved_rip_overwrite = bool(candidate.get("saved_rip_overwrite"))
    shadow_stack_sync = bool(candidate.get("shadow_stack_sync_evidence"))
    indirect_branch = bool(candidate.get("uses_indirect_branch"))
    endbr_target = bool(candidate.get("indirect_target_endbr_evidence"))

    blockers: list[str] = []
    if not saved_rip_overwrite:
        blockers.append("saved_return_address_overwrite_not_proven")
    if saved_rip_overwrite and policy.shadow_stack_enforced and not shadow_stack_sync:
        blockers.append("shadow_stack_return_mismatch")
    if indirect_branch and policy.ibt_enforced and policy.endbr_enforced_for_indirect_targets and not endbr_target:
        blockers.append("ibt_target_without_reviewed_endbr")

    executable_control = saved_rip_overwrite and not blockers
    return {
        "kind": "reviewed_control_flow_enforcement_assessment",
        "state": "derived_static",
        "runtime_observed": False,
        "candidate": dict(candidate),
        "policy": asdict(policy),
        "saved_rip_overwrite": saved_rip_overwrite,
        "executable_control": executable_control,
        "blockers": blockers,
        "provenance": policy.provenance,
        "limitations": [
            "saved RIP control and executable control are separate facts",
            "passing this policy gate does not prove gadget semantics or exploit success",
            "CET state comes from reviewed runtime evidence, not ELF feature names alone",
        ],
    }
