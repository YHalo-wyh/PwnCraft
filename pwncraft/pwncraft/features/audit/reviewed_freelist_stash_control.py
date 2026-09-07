"""Reviewed allocator/control-flow helpers for later exploit-state composition.

This module only composes already-reviewed facts.  Technique/challenge names are
not inputs and no capability is promoted beyond the exact state demonstrated by
its policy.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SafeLinkedFreelistPolicy:
    name: str
    allocator_family: str
    allocator_version: str
    safe_linking_enabled: bool
    pointer_shift: int
    alignment: int
    storage_address: int
    encoded_next: int
    target_user_address: int
    cache_count_before_pop: int
    required_pop_index: int
    provenance: str = "REVIEWED_SAFE_LINKED_FREELIST_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("freelist policy identity must be complete")
        if self.pointer_shift < 0 or self.alignment <= 0:
            raise ValueError("safe-link geometry must be valid")
        if min(self.storage_address, self.encoded_next, self.target_user_address) < 0:
            raise ValueError("freelist addresses must be non-negative")
        if self.cache_count_before_pop <= 0 or self.required_pop_index <= 0:
            raise ValueError("pop geometry must be positive")


@dataclass(frozen=True)
class SmallbinTcacheStashPolicy:
    name: str
    allocator_family: str
    allocator_version: str
    returned_head: int
    traversal_user_addresses: tuple[int, ...]
    tcache_count_before_stash: int
    tcache_capacity: int
    requested_pop_index: int
    expected_return_address: int
    integrity_reviewed: bool
    provenance: str = "REVIEWED_SMALLBIN_TCACHE_STASH_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("stash policy identity must be complete")
        if self.returned_head < 0 or self.expected_return_address < 0:
            raise ValueError("stash addresses must be non-negative")
        if not self.traversal_user_addresses:
            raise ValueError("stash traversal must be non-empty")
        if any(address < 0 for address in self.traversal_user_addresses):
            raise ValueError("stash traversal addresses must be non-negative")
        if not 0 <= self.tcache_count_before_stash <= self.tcache_capacity:
            raise ValueError("tcache count outside capacity")
        if self.tcache_capacity <= 0 or self.requested_pop_index <= 0:
            raise ValueError("stash capacity/pop index must be positive")


@dataclass(frozen=True)
class PacSpeculationPolicy:
    name: str
    architecture: str
    protected_region_start: int
    protected_region_end: int
    tag_bits: int
    tag_high_bit: int
    probe_address: int
    target_address: int
    good_tag_speculative_loads_probe: bool
    bad_tag_speculative_loads_probe: bool
    speculative_bad_tag_commits_fault: bool
    timing_hit_distinguishable: bool
    provenance: str = "REVIEWED_PAC_SPECULATION_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.architecture.strip():
            raise ValueError("PAC policy identity must be complete")
        if not 0 <= self.protected_region_start < self.protected_region_end:
            raise ValueError("protected region must be valid")
        if self.tag_bits <= 0 or self.tag_bits > 16 or self.tag_high_bit < self.tag_bits - 1:
            raise ValueError("tag geometry is invalid")
        if self.probe_address < 0 or self.target_address < 0:
            raise ValueError("PAC addresses must be non-negative")


def _has_capability(fact: dict[str, Any], capability: str) -> bool:
    return capability in (fact.get("capabilities") or [])


def derive_safe_linked_freelist_return(
    upstream: dict[str, Any],
    policy: SafeLinkedFreelistPolicy,
) -> dict[str, Any] | None:
    """Prove one safe-linked freelist retarget and the exact later pop identity."""
    policy.validate()
    if not _has_capability(upstream, "same_identity_cross_bin_membership"):
        return None
    if not policy.safe_linking_enabled:
        return None
    if policy.target_user_address % policy.alignment != 0:
        return None
    if policy.required_pop_index > policy.cache_count_before_pop:
        return None

    expected_encoded = policy.target_user_address ^ (policy.storage_address >> policy.pointer_shift)
    if policy.encoded_next != expected_encoded:
        return None

    facts = [
        {
            "kind": "safe_link_pointer_encoding_matches",
            "storage_address": policy.storage_address,
            "target_user_address": policy.target_user_address,
            "pointer_shift": policy.pointer_shift,
            "encoded_next": policy.encoded_next,
        },
        {
            "kind": "tcache_next_pointer_retargeted",
            "storage_address": policy.storage_address,
            "decoded_next": policy.target_user_address,
        },
        {
            "kind": "reviewed_cache_pop_returns_target",
            "pop_index": policy.required_pop_index,
            "returned_user_address": policy.target_user_address,
        },
    ]
    return {
        "kind": "reviewed_safe_linked_freelist_return",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": asdict(policy),
        "facts": facts,
        "capabilities": ["controlled_tcache_allocation_target"],
        "provenance": policy.provenance,
        "limitations": [
            "this proves one reviewed allocation target, not unrestricted arbitrary allocation",
            "it does not prove a later metadata write, largebin attack, FSOP or exploit success",
            "safe-linking parameters and cache-pop state are reviewed facts, not guessed from glibc version names",
        ],
    }


def derive_smallbin_tcache_stash_return(
    upstream: dict[str, Any],
    policy: SmallbinTcacheStashPolicy,
) -> dict[str, Any] | None:
    """Derive tcache stash order and a later returned user address."""
    policy.validate()
    if not upstream.get("bounded_adjacent_metadata_overwrite"):
        return None
    if not policy.integrity_reviewed:
        return None
    room = policy.tcache_capacity - policy.tcache_count_before_stash
    if room < len(policy.traversal_user_addresses):
        return None

    # glibc's reviewed stash traversal pushes each traversed user pointer to
    # tcache in traversal order.  The cache is LIFO, so later mallocs pop the
    # reverse sequence.
    pop_order = list(reversed(policy.traversal_user_addresses))
    if policy.requested_pop_index > len(pop_order):
        return None
    returned = pop_order[policy.requested_pop_index - 1]
    if returned != policy.expected_return_address:
        return None

    return {
        "kind": "reviewed_smallbin_tcache_stash_return",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "smallbin_tcache_stash_sequence",
                "returned_head": policy.returned_head,
                "traversal_user_addresses": list(policy.traversal_user_addresses),
            },
            {"kind": "tcache_lifo_after_stash", "pop_order": pop_order},
            {
                "kind": "nth_allocation_returns_reviewed_user",
                "pop_index": policy.requested_pop_index,
                "returned_user_address": returned,
            },
        ],
        "capabilities": ["reviewed_fake_user_allocation_acquired"],
        "provenance": policy.provenance,
        "limitations": [
            "the traversal/list integrity is an explicit reviewed precondition",
            "this does not by itself prove arbitrary-address allocation or a FILE/Apple2 chain",
            "House-of-* names are not used as semantic evidence",
        ],
    }


def derive_pac_speculative_tag_oracle(policy: PacSpeculationPolicy) -> dict[str, Any] | None:
    """Derive a finite PAC-tag timing oracle from reviewed speculative behavior."""
    policy.validate()
    if not (policy.protected_region_start <= policy.target_address < policy.protected_region_end):
        return None
    if not policy.good_tag_speculative_loads_probe:
        return None
    if policy.bad_tag_speculative_loads_probe:
        return None
    if policy.speculative_bad_tag_commits_fault:
        return None
    if not policy.timing_hit_distinguishable:
        return None

    candidate_count = 1 << policy.tag_bits
    return {
        "kind": "reviewed_pac_speculative_tag_oracle",
        "state": "derived_static",
        "runtime_observed": False,
        "architecture": policy.architecture,
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "speculative_pac_tag_cache_oracle",
                "probe_address": policy.probe_address,
                "candidate_count": candidate_count,
                "good_guess_effect": "probe_cache_fill",
                "bad_guess_effect": "no_probe_load_no_committed_fault",
            },
            {
                "kind": "finite_tag_search_space",
                "tag_bits": policy.tag_bits,
                "candidate_count": candidate_count,
            },
            {
                "kind": "authenticated_indirect_target_after_tag_recovery",
                "target_address": policy.target_address,
            },
        ],
        "capabilities": ["pac_tag_recoverable_via_reviewed_timing_oracle"],
        "provenance": policy.provenance,
        "limitations": [
            "this is a static reviewed oracle model, not an observed timing trace",
            "it does not infer the PAC key or tag value before measurements",
            "it does not generalize to architectures/cores without the reviewed speculative cache behavior",
        ],
    }
