"""Reviewed exact tcache-metadata allocation targeting.

This layer composes an already-acquired tcache metadata user with an observed
runtime libc base and one reviewed tcache entry rewrite.  It proves only the
next allocation for one exact size class and one exact target.  It deliberately
does not promote the state to unrestricted arbitrary allocation or FILE/FSOP.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ExactTcacheMetadataTargetPolicy:
    name: str
    allocator_family: str
    allocator_version: str
    metadata_user_address: int
    tcache_entries_base: int
    target_entry_index: int
    pointer_width: int
    request_size: int
    chunk_size: int
    target_libc_offset: int
    target_address: int
    tcache_count_positive_reviewed: bool = False
    entry_write_reviewed: bool = False
    allocation_semantics_reviewed: bool = False
    provenance: str = "REVIEWED_EXACT_TCACHE_METADATA_TARGET_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("tcache target policy identity must be complete")
        numeric = (
            self.metadata_user_address,
            self.tcache_entries_base,
            self.target_entry_index,
            self.pointer_width,
            self.request_size,
            self.chunk_size,
            self.target_libc_offset,
            self.target_address,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("tcache target addresses/geometry must be non-negative")
        if self.pointer_width <= 0 or self.request_size <= 0 or self.chunk_size <= 0:
            raise ValueError("tcache target widths/sizes must be positive")
        if self.request_size >= self.chunk_size:
            raise ValueError("reviewed request must fit inside the reviewed chunk size")


def _metadata_user(upstream: dict[str, Any]) -> int | None:
    if "reviewed_fake_user_allocation_acquired" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "nth_allocation_returns_reviewed_user":
            value = fact.get("returned_user_address")
            return int(value) if isinstance(value, int) else None
    return None


def _observed_libc_base(upstream: dict[str, Any]) -> int | None:
    if "libc_base_derived_from_stdout_observation" not in (upstream.get("capabilities") or []):
        return None
    if upstream.get("runtime_observed") is not True:
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "libc_base_formula":
            value = fact.get("result")
            return int(value) if isinstance(value, int) else None
    return None


def derive_exact_tcache_metadata_target(
    metadata_upstream: dict[str, Any],
    libc_upstream: dict[str, Any],
    policy: ExactTcacheMetadataTargetPolicy,
) -> dict[str, Any] | None:
    """Prove one exact next allocation returned by a reviewed tcache entry.

    Both upstream layers are mandatory: the metadata user must already be
    acquired and the libc base must come from an actual runtime observation.
    The rule then checks entry geometry, target = libc_base + reviewed offset,
    a positive reviewed count, the reviewed entry write and the reviewed size
    class allocation semantics.
    """
    policy.validate()
    metadata_user = _metadata_user(metadata_upstream)
    libc_base = _observed_libc_base(libc_upstream)
    if metadata_user != policy.metadata_user_address or libc_base is None:
        return None
    if policy.metadata_user_address != policy.tcache_entries_base:
        return None

    entry_address = policy.tcache_entries_base + policy.target_entry_index * policy.pointer_width
    expected_target = libc_base + policy.target_libc_offset
    if expected_target != policy.target_address:
        return None
    if not (
        policy.tcache_count_positive_reviewed
        and policy.entry_write_reviewed
        and policy.allocation_semantics_reviewed
    ):
        return None

    return {
        "kind": "reviewed_exact_tcache_metadata_target",
        "state": "derived_runtime_bound",
        "runtime_observed": True,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "reviewed_tcache_entry_exact_write",
                "entry_index": policy.target_entry_index,
                "entry_address": entry_address,
                "value": policy.target_address,
                "width": policy.pointer_width,
            },
            {
                "kind": "reviewed_tcache_count_positive_before_allocation",
                "chunk_size": policy.chunk_size,
            },
            {
                "kind": "reviewed_libc_relative_allocation_target",
                "libc_base": libc_base,
                "target_libc_offset": policy.target_libc_offset,
                "target_address": policy.target_address,
            },
            {
                "kind": "reviewed_next_allocation_returns_exact_target",
                "request_size": policy.request_size,
                "chunk_size": policy.chunk_size,
                "returned_user_address": policy.target_address,
            },
        ],
        "capabilities": ["reviewed_exact_tcache_allocation_target"],
        "provenance": policy.provenance,
        "limitations": [
            "this proves one reviewed next allocation target for one reviewed size class, not unrestricted arbitrary allocation",
            "the target is runtime-bound to an observed libc base and cannot be emitted from a static libc candidate",
            "later wide-data, vtable, FILE, control-transfer, shell or flag semantics require separate reviewed layers",
        ],
    }
