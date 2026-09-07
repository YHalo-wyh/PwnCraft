"""Deterministic format-string target/write planning.

The planner is intentionally lower-level than pwntools fmtstr_payload: it
binds exact target addresses, splits a concrete value into write atoms, and
computes modulo padding. Unknown target/value/writability stays unknown.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass


_SPECIFIER = {8: "hhn", 16: "hn", 32: "n"}


@dataclass(frozen=True)
class ExactFormatWritePolicy:
    name: str
    target_address: int | None
    desired_value: int | None
    first_pointer_argument: int
    total_bits: int
    atom_bits: int
    initial_count: int = 0
    target_writable_reviewed: bool | None = None
    endianness: str = "little"
    provenance: str = "REVIEWED_EXACT_FORMAT_WRITE_POLICY"

    def validate_shape(self) -> None:
        if not self.name.strip():
            raise ValueError("format policy name is required")
        if self.first_pointer_argument <= 0:
            raise ValueError("format argument positions are 1-based")
        if self.atom_bits not in _SPECIFIER:
            raise ValueError("supported atom widths are 8/16/32")
        if self.total_bits <= 0 or self.total_bits % self.atom_bits:
            raise ValueError("total width must be a positive multiple of atom width")
        if self.endianness not in ("little", "big"):
            raise ValueError("endianness must be explicit")
        if self.initial_count < 0:
            raise ValueError("initial printed count must be non-negative")


def derive_exact_format_write_plan(policy: ExactFormatWritePolicy) -> dict | None:
    """Return an exact modulo-padding plan only when every required value is known."""
    policy.validate_shape()
    if policy.target_address is None or policy.desired_value is None:
        return None
    if policy.target_writable_reviewed is not True:
        return None
    if policy.target_address < 0 or policy.desired_value < 0:
        return None
    if policy.desired_value >= (1 << policy.total_bits):
        return None

    atom_bytes = policy.atom_bits // 8
    atom_count = policy.total_bits // policy.atom_bits
    modulus = 1 << policy.atom_bits
    mask = modulus - 1

    atoms = []
    for index in range(atom_count):
        if policy.endianness == "little":
            shift = index * policy.atom_bits
            address = policy.target_address + index * atom_bytes
        else:
            shift = (atom_count - 1 - index) * policy.atom_bits
            address = policy.target_address + index * atom_bytes
        atoms.append({
            "address": address,
            "value": (policy.desired_value >> shift) & mask,
        })

    scheduled = sorted(atoms, key=lambda atom: (atom["value"], atom["address"]))
    current = policy.initial_count % modulus
    writes = []
    for ordinal, atom in enumerate(scheduled):
        padding = (atom["value"] - current) % modulus
        current = (current + padding) % modulus
        writes.append({
            "argument_index": policy.first_pointer_argument + ordinal,
            "address": atom["address"],
            "value": atom["value"],
            "padding": padding,
            "modulus": modulus,
            "specifier": _SPECIFIER[policy.atom_bits],
            "count_after": current,
        })

    return {
        "kind": "reviewed_exact_format_write_plan",
        "state": "derived_static",
        "runtime_observed": False,
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "reviewed_writable_format_target",
                "address": policy.target_address,
                "width": policy.total_bits // 8,
            },
            {
                "kind": "exact_format_write_atoms",
                "atom_bits": policy.atom_bits,
                "atoms": atoms,
            },
            {
                "kind": "exact_modulo_padding_plan",
                "initial_count": policy.initial_count,
                "writes": writes,
            },
        ],
        "capabilities": ["exact_format_write_plan"],
        "provenance": policy.provenance,
        "limitations": [
            "this is an arithmetic write plan, not proof the payload reaches printf",
            "target writability must be reviewed independently",
            "unknown target addresses or desired values are never substituted with guessed constants",
        ],
    }
