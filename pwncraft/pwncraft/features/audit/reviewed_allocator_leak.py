"""Reviewed allocator-to-leak compositions for glibc-style metadata workflows.

Static pointer seeding, candidate partial retargeting, and runtime leak/base
derivation are deliberately separate facts.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class UnsortedTcacheLibcSeedPolicy:
    name: str
    allocator_family: str
    allocator_version: str
    acquired_metadata_user_address: int
    tcache_entries_base: int
    fake_user_address: int
    fake_chunk_header_address: int
    chunk_header_size: int
    fake_chunk_size: int
    target_entry_index: int
    pointer_width: int
    tcache_count_before_free: int
    tcache_capacity: int
    unsorted_insert_reviewed: bool
    libc_pointer_write_reviewed: bool
    provenance: str = "REVIEWED_UNSORTED_TCACHE_LIBC_SEED_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.allocator_family.strip() or not self.allocator_version.strip():
            raise ValueError("allocator leak policy identity must be complete")
        numeric = (
            self.acquired_metadata_user_address,
            self.tcache_entries_base,
            self.fake_user_address,
            self.fake_chunk_header_address,
            self.chunk_header_size,
            self.fake_chunk_size,
            self.target_entry_index,
            self.pointer_width,
            self.tcache_count_before_free,
            self.tcache_capacity,
        )
        if any(v < 0 for v in numeric):
            raise ValueError("allocator leak geometry must be non-negative")
        if self.pointer_width <= 0 or self.chunk_header_size <= 0 or self.fake_chunk_size <= 0:
            raise ValueError("allocator leak widths must be positive")
        if self.tcache_count_before_free > self.tcache_capacity:
            raise ValueError("tcache count exceeds capacity")


def _acquired_fake_user(upstream: dict[str, Any]) -> int | None:
    if "reviewed_fake_user_allocation_acquired" not in (upstream.get("capabilities") or []):
        return None
    for fact in upstream.get("facts") or []:
        if isinstance(fact, dict) and fact.get("kind") == "nth_allocation_returns_reviewed_user":
            value = fact.get("returned_user_address")
            return int(value) if isinstance(value, int) else None
    return None


def derive_unsorted_tcache_libc_seed(
    upstream: dict[str, Any],
    policy: UnsortedTcacheLibcSeedPolicy,
) -> dict[str, Any] | None:
    """Prove that reviewed unsorted fd/bk writes land in tcache entries."""
    policy.validate()
    if _acquired_fake_user(upstream) != policy.acquired_metadata_user_address:
        return None
    if policy.acquired_metadata_user_address != policy.tcache_entries_base:
        return None
    if policy.fake_user_address != policy.tcache_entries_base + policy.target_entry_index * policy.pointer_width:
        return None
    if policy.fake_chunk_header_address + policy.chunk_header_size != policy.fake_user_address:
        return None
    if policy.tcache_count_before_free != policy.tcache_capacity:
        return None
    if not (policy.unsorted_insert_reviewed and policy.libc_pointer_write_reviewed):
        return None

    return {
        "kind": "reviewed_unsorted_tcache_libc_seed",
        "state": "derived_static",
        "runtime_observed": False,
        "allocator": {"family": policy.allocator_family, "version": policy.allocator_version},
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "fake_chunk_bypasses_full_tcache",
                "fake_chunk_header_address": policy.fake_chunk_header_address,
                "fake_chunk_size": policy.fake_chunk_size,
            },
            {
                "kind": "unsorted_fd_bk_overlap_tcache_entries",
                "fd_target_entry": policy.target_entry_index,
                "bk_target_entry": policy.target_entry_index + 1,
                "fd_address": policy.fake_user_address,
                "bk_address": policy.fake_user_address + policy.pointer_width,
            },
            {
                "kind": "libc_origin_pointer_seeded_into_tcache_entry",
                "entry_index": policy.target_entry_index,
                "entry_address": policy.fake_user_address,
                "pointer_origin": "reviewed_unsorted_bin_link",
            },
        ],
        "capabilities": ["libc_pointer_seeded_in_tcache_metadata"],
        "provenance": policy.provenance,
        "limitations": [
            "the concrete libc pointer value is runtime-dependent",
            "a seeded libc-origin pointer is not yet a stdout allocation",
            "House-of-Apple/FILE execution is not inferred from this metadata fact",
        ],
    }


@dataclass(frozen=True)
class StdoutLow16CandidatePolicy:
    name: str
    tcache_entries_base: int
    target_entry_index: int
    pointer_width: int
    libc_low_nibble_guess: int
    stdout_symbol_offset: int
    low_bits: int = 16
    provenance: str = "REVIEWED_STDOUT_LOW16_CANDIDATE_POLICY"

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("stdout candidate policy name is required")
        if min(self.tcache_entries_base, self.target_entry_index, self.pointer_width,
               self.libc_low_nibble_guess, self.stdout_symbol_offset, self.low_bits) < 0:
            raise ValueError("stdout candidate geometry must be non-negative")
        if self.pointer_width <= 0 or self.low_bits <= 0 or self.low_bits > 32:
            raise ValueError("stdout candidate widths are invalid")
        if self.libc_low_nibble_guess > 0xF:
            raise ValueError("libc low nibble guess must be 0..15")


def derive_stdout_low16_candidate(
    upstream: dict[str, Any],
    policy: StdoutLow16CandidatePolicy,
) -> dict[str, Any] | None:
    """Derive one partial-pointer candidate; never assert the guess is correct."""
    policy.validate()
    if "libc_pointer_seeded_in_tcache_metadata" not in (upstream.get("capabilities") or []):
        return None
    entry = policy.tcache_entries_base + policy.target_entry_index * policy.pointer_width
    modulus = 1 << policy.low_bits
    candidate_low = (((policy.libc_low_nibble_guess & 0xF) << 12) + policy.stdout_symbol_offset) % modulus
    return {
        "kind": "reviewed_stdout_low16_candidate",
        "state": "derived_static",
        "runtime_observed": False,
        "facts": [
            {
                "kind": "stdout_low16_candidate_retarget",
                "entry_index": policy.target_entry_index,
                "entry_address": entry,
                "low_bits": policy.low_bits,
                "candidate_low_value": candidate_low,
                "guess": policy.libc_low_nibble_guess,
            },
            {
                "kind": "finite_partial_pointer_candidate_space",
                "candidate_count": 16,
                "guess_bits": 4,
            },
        ],
        "capabilities": ["stdout_partial_retarget_candidate"],
        "provenance": policy.provenance,
        "limitations": [
            "the low-nibble guess is a candidate, not an observed correct libc base",
            "malloc returning stdout requires the candidate to be correct and the reviewed tcache state to hold",
            "no libc base is derived before an actual pointer observation",
        ],
    }


def derive_libc_base_from_stdout_observation(
    leaked_pointer: int,
    *,
    stdout_symbol_offset: int,
    observed_field_offset: int,
    accepted_top40: tuple[int, ...] = (0x7F, 0x7E),
    provenance: str = "RUNTIME_STDOUT_LEAK_OBSERVATION",
) -> dict[str, Any] | None:
    """Derive libc base from one observed pointer with an explicit formula."""
    leaked_pointer = int(leaked_pointer)
    stdout_symbol_offset = int(stdout_symbol_offset)
    observed_field_offset = int(observed_field_offset)
    if min(leaked_pointer, stdout_symbol_offset, observed_field_offset) < 0:
        return None
    if (leaked_pointer >> 40) not in accepted_top40:
        return None
    delta = stdout_symbol_offset + observed_field_offset
    if leaked_pointer < delta:
        return None
    base = leaked_pointer - delta
    return {
        "kind": "runtime_stdout_libc_base_derivation",
        "state": "observed_runtime",
        "runtime_observed": True,
        "facts": [
            {"kind": "observed_libc_pointer", "value": leaked_pointer},
            {
                "kind": "libc_base_formula",
                "expression": "leaked_pointer - (stdout_symbol_offset + observed_field_offset)",
                "stdout_symbol_offset": stdout_symbol_offset,
                "observed_field_offset": observed_field_offset,
                "result": base,
            },
        ],
        "capabilities": ["libc_base_derived_from_stdout_observation"],
        "provenance": provenance,
        "limitations": [
            "the base depends on the reviewed identity of the observed stdout-relative field",
            "this does not prove a later FILE corruption or control-flow transfer",
        ],
    }
