"""ELF/runtime binding for exact format-string GOT rebind plans.

This layer consumes deterministic ELF artifact evidence plus one observed runtime
libc symbol address.  It resolves one import relocation, verifies that the target
remains writable after RELRO, derives the exact libc base from the observed
symbol, resolves the desired libc symbol, and only then delegates arithmetic to
the exact format-write planner.

It does not prove that attacker-controlled bytes reach printf, that a later call
hits the rebound GOT entry, or that the desired symbol yields exploit success.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from pwncraft.core.elf_artifact_provider import (
    ElfArtifactSnapshot,
    address_is_runtime_writable,
    relocation_runtime_address,
    relocations_for_symbol,
    resolve_symbol,
    runtime_symbol_address,
)
from pwncraft.features.audit.reviewed_format_plan import (
    ExactFormatWritePolicy,
    derive_exact_format_write_plan,
)


@dataclass(frozen=True)
class ElfFormatGotRebindPolicy:
    name: str
    target_import_name: str
    observed_libc_symbol: str
    desired_libc_symbol: str
    observed_libc_symbol_address: int
    first_pointer_argument: int
    total_bits: int
    atom_bits: int
    initial_count: int = 0
    main_load_base: int | None = None
    provenance: str = "ELF_RUNTIME_BOUND_FORMAT_GOT_POLICY"

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("format ELF binding policy name is required")
        if not all(value.strip() for value in (
            self.target_import_name,
            self.observed_libc_symbol,
            self.desired_libc_symbol,
        )):
            raise ValueError("format ELF binding symbolic fields are required")
        if self.observed_libc_symbol_address < 0:
            raise ValueError("observed libc symbol address must be non-negative")
        if self.first_pointer_argument <= 0:
            raise ValueError("format pointer argument is 1-based")
        if self.total_bits <= 0 or self.atom_bits <= 0:
            raise ValueError("format write widths must be positive")
        if self.main_load_base is not None and self.main_load_base < 0:
            raise ValueError("main load base must be non-negative when supplied")


def _main_relocation_address(
    main: ElfArtifactSnapshot,
    relocation: Any,
    policy: ElfFormatGotRebindPolicy,
) -> int | None:
    if main.elf_type == "EXEC":
        return relocation_runtime_address(main, relocation, load_base=0)
    if main.elf_type == "DYN":
        if policy.main_load_base is None:
            return None
        return relocation_runtime_address(main, relocation, load_base=policy.main_load_base)
    return None


def _libc_base_from_observation(
    libc: ElfArtifactSnapshot,
    policy: ElfFormatGotRebindPolicy,
) -> tuple[int, int] | None:
    observed_symbol = resolve_symbol(libc, policy.observed_libc_symbol)
    if observed_symbol is None:
        return None
    if libc.elf_type != "DYN":
        return None
    if policy.observed_libc_symbol_address < observed_symbol.value:
        return None
    libc_base = policy.observed_libc_symbol_address - observed_symbol.value
    desired = runtime_symbol_address(libc, policy.desired_libc_symbol, load_base=libc_base)
    if desired is None:
        return None
    return libc_base, desired


def derive_elf_bound_format_got_rebind_plan(
    main: ElfArtifactSnapshot,
    libc: ElfArtifactSnapshot,
    policy: ElfFormatGotRebindPolicy,
) -> dict[str, Any] | None:
    """Derive one exact GOT write plan from artifact + runtime evidence."""
    policy.validate()
    if main.degraded or libc.degraded:
        return None

    relocations = relocations_for_symbol(main, policy.target_import_name)
    if len(relocations) != 1:
        return None
    relocation = relocations[0]
    target_address = _main_relocation_address(main, relocation, policy)
    if target_address is None:
        return None
    # Writability is checked against the artifact-relative relocation offset;
    # ASLR changes the runtime address but not PT_LOAD/PT_GNU_RELRO membership.
    if not address_is_runtime_writable(main, relocation.offset):
        return None

    libc_binding = _libc_base_from_observation(libc, policy)
    if libc_binding is None:
        return None
    libc_base, desired_address = libc_binding

    exact_plan = derive_exact_format_write_plan(ExactFormatWritePolicy(
        name=policy.name,
        target_address=target_address,
        desired_value=desired_address,
        first_pointer_argument=policy.first_pointer_argument,
        total_bits=policy.total_bits,
        atom_bits=policy.atom_bits,
        initial_count=policy.initial_count,
        target_writable_reviewed=True,
        endianness="little" if "little endian" in libc.data_encoding.lower() else "big",
        provenance=policy.provenance,
    ))
    if exact_plan is None:
        return None

    observed_symbol = resolve_symbol(libc, policy.observed_libc_symbol)
    desired_symbol = resolve_symbol(libc, policy.desired_libc_symbol)
    assert observed_symbol is not None and desired_symbol is not None
    return {
        "kind": "reviewed_elf_bound_format_got_rebind_plan",
        "state": "derived_runtime_bound",
        "runtime_observed": True,
        "policy": asdict(policy),
        "artifacts": {
            "main_sha256": main.artifact_sha256,
            "libc_sha256": libc.artifact_sha256,
        },
        "facts": [
            {
                "kind": "reviewed_import_relocation_target",
                "symbol": policy.target_import_name,
                "relocation_type": relocation.relocation_type,
                "artifact_offset": relocation.offset,
                "runtime_address": target_address,
                "runtime_writable": True,
            },
            {
                "kind": "observed_libc_symbol_base_derivation",
                "symbol": policy.observed_libc_symbol,
                "observed_address": policy.observed_libc_symbol_address,
                "symbol_offset": observed_symbol.value,
                "libc_base": libc_base,
            },
            {
                "kind": "reviewed_desired_libc_symbol_address",
                "symbol": policy.desired_libc_symbol,
                "symbol_offset": desired_symbol.value,
                "runtime_address": desired_address,
            },
        ],
        "write_plan": exact_plan,
        "capabilities": ["elf_bound_exact_format_got_rebind_plan"],
        "provenance": policy.provenance,
        "limitations": [
            "the runtime libc base depends on the supplied observed symbol address",
            "a writable import relocation and exact modulo plan do not prove payload reachability",
            "the later program call site and desired-symbol behavior require separate reviewed evidence",
        ],
    }
