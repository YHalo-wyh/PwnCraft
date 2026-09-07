"""Reviewed largebin pointer-write composition.

This module consumes an already-proven controlled allocation and an explicit
allocator policy. It does not recognize House-of-* names and it never promotes
a metadata write into FILE/FSOP execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class LargebinPointerWritePolicy:
    name: str
    allocator_family: str
    allocator_version: str
    controlled_user_address: int
    large_chunk_header_address: int
    fd_nextsize_value: int
    bk_nextsize_value: int
    inserted_chunk_header_address: int
    target_address: int
    fd_nextsize_offset: int = 0x20
    bk_nextsize_offset: int = 0x28
    target_field_bias: int = 0x20
    write_width: int = 8
    inserted_chunk_is_smaller: bool = False
    insertion_semantics_reviewed: bool = False
    target_writable_reviewed: bool = False
    provenance: str = "REVIEWED_LARGEBIN_POINTER_WRITE_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("largebin policy identity must be complete")
        numeric = (
            self.controlled_user_address,
            self.large_chunk_header_address,
            self.fd_nextsize_value,
            self.bk_nextsize_value,
            self.inserted_chunk_header_address,
            self.target_address,
            self.fd_nextsize_offset,
            self.bk_nextsize_offset,
            self.target_field_bias,
            self.write_width,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("largebin addresses/offsets must be non-negative")
        if self.write_width <= 0:
            raise ValueError("write width must be positive")
        if self.fd_nextsize_offset >= self.bk_nextsize_offset:
            raise ValueError("reviewed largebin field order is invalid")


def _reviewed_returned_user(upstream: dict[str, Any]) -> int | None:
    if "controlled_tcache_allocation_target" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "reviewed_cache_pop_returns_target":
            value = fact.get("returned_user_address")
            return int(value) if isinstance(value, int) else None
    return None


def derive_largebin_pointer_write(
    upstream: dict[str, Any],
    policy: LargebinPointerWritePolicy,
) -> dict[str, Any] | None:
    """Prove one reviewed largebin insertion pointer write.

    The controlled allocation must begin exactly at the large chunk's
    fd_nextsize field. The reviewed payload must make fd_nextsize self-pointing
    and bk_nextsize point to ``target - target_field_bias``. Only then can the
    reviewed insertion of the smaller victim promote to an exact pointer write.
    """
    policy.validate()
    returned = _reviewed_returned_user(upstream)
    if returned != policy.controlled_user_address:
        return None
    if policy.controlled_user_address != policy.large_chunk_header_address + policy.fd_nextsize_offset:
        return None
    if policy.fd_nextsize_value != policy.large_chunk_header_address:
        return None
    if policy.bk_nextsize_value + policy.target_field_bias != policy.target_address:
        return None
    if not (
        policy.inserted_chunk_is_smaller
        and policy.insertion_semantics_reviewed
        and policy.target_writable_reviewed
    ):
        return None

    return {
        "kind": "reviewed_largebin_pointer_write",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "controlled_largebin_metadata_fields",
                "chunk_header_address": policy.large_chunk_header_address,
                "fd_nextsize_address": policy.large_chunk_header_address + policy.fd_nextsize_offset,
                "fd_nextsize_value": policy.fd_nextsize_value,
                "bk_nextsize_address": policy.large_chunk_header_address + policy.bk_nextsize_offset,
                "bk_nextsize_value": policy.bk_nextsize_value,
            },
            {
                "kind": "reviewed_smaller_largebin_insertion",
                "inserted_chunk_header_address": policy.inserted_chunk_header_address,
            },
            {
                "kind": "largebin_insertion_pointer_write",
                "address": policy.target_address,
                "value": policy.inserted_chunk_header_address,
                "width": policy.write_width,
            },
        ],
        "capabilities": ["reviewed_largebin_pointer_write"],
        "provenance": policy.provenance,
        "limitations": [
            "the write is the exact reviewed largebin insertion side effect, not an unrestricted arbitrary write",
            "the written pointer's FILE/stdio meaning is a separate layer",
            "no FSOP reachability, vtable semantics, control transfer or exploit success is inferred here",
        ],
    }
