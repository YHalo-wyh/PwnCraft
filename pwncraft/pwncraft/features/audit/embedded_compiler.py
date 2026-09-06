"""Reviewed compiler-semantics layer for typed embedded programs.

This module is deliberately policy-gated.  Embedded source structure alone does
not prove how a target compiler computes liveness or allocates local slots.
Callers must provide an explicit reviewed policy before any compiler-semantic
fact is derived.

Cycle-16 is motivated by SCTF 2026 ``slang``.  Its official writeup documents a
compiler rule where arguments of loop-local calls returning ``void`` are skipped
by the allocation liveness scan while code generation still emits those
arguments.  Combined with first-fit reuse of non-overlapping live intervals, the
source program can therefore place differently typed locals in the same slot.

The implementation is generic: no challenge names, function names, addresses or
payload hashes are embedded here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any

from pwncraft.features.audit.embedded_program import EmbeddedFunction, EmbeddedProgram


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SUPPORTED_SLOT_ALLOCATORS = {"first_fit_nonoverlap"}


@dataclass(frozen=True)
class EmbeddedCompilerPolicy:
    name: str
    skip_loop_void_call_arguments_in_liveness: bool
    codegen_preserves_call_arguments: bool
    slot_allocator: str = "first_fit_nonoverlap"
    provenance: str = "REVIEWED_COMPILER_POLICY"

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("compiler policy name must be non-empty")
        if self.slot_allocator not in _SUPPORTED_SLOT_ALLOCATORS:
            raise ValueError(f"unsupported embedded slot allocator: {self.slot_allocator}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _Lifetime:
    name: str
    type_name: str
    declaration_index: int
    first_order: int
    last_order: int
    definition_orders: tuple[int, ...]
    effective_use_orders: tuple[int, ...]
    omitted_use_orders: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("definition_orders", "effective_use_orders", "omitted_use_orders"):
            data[key] = list(data[key])
        return data


def _strip_strings(text: str) -> str:
    """Remove quoted-string contents before identifier extraction."""
    out: list[str] = []
    quote = ""
    escaped = False
    for char in text:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            out.append(" ")
            continue
        if char in ("'", '"'):
            quote = char
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def _local_identifiers(text: str, local_names: set[str]) -> list[str]:
    return [name for name in _IDENT_RE.findall(_strip_strings(text)) if name in local_names]


def _function_return_types(program: EmbeddedProgram) -> dict[str, str]:
    return {fn.name: fn.return_type for fn in program.functions}


def _analyze_function(
    function: EmbeddedFunction,
    return_types: dict[str, str],
    policy: EmbeddedCompilerPolicy,
) -> dict[str, Any]:
    local_types = {item.name: item.type_name for item in function.locals}
    local_names = set(local_types)
    declaration_index = {item.name: index for index, item in enumerate(function.locals)}

    definitions: dict[str, list[int]] = {name: [] for name in local_names}
    effective_uses: dict[str, list[int]] = {name: [] for name in local_names}
    omitted_uses: dict[str, list[int]] = {name: [] for name in local_names}
    omissions: list[dict[str, Any]] = []

    for statement in function.statements:
        if statement.kind == "assignment" and statement.target in local_names:
            # RHS uses happen before the target definition at the same source step.
            for name in _local_identifiers(statement.expression, local_names):
                effective_uses[name].append(statement.order)
            definitions[statement.target].append(statement.order)
            continue

        if statement.kind != "call":
            continue

        argument_names: list[str] = []
        for argument in statement.arguments:
            argument_names.extend(_local_identifiers(argument, local_names))

        callee_return = return_types.get(statement.callee)
        skip_arguments = bool(
            policy.skip_loop_void_call_arguments_in_liveness
            and statement.loop_depth > 0
            and callee_return == "void"
        )
        if skip_arguments:
            for name in argument_names:
                omitted_uses[name].append(statement.order)
            if argument_names:
                omissions.append({
                    "kind": "loop_void_call_argument_liveness_omission",
                    "function": function.name,
                    "callee": statement.callee,
                    "callee_return_type": callee_return,
                    "line": statement.line,
                    "order": statement.order,
                    "loop_depth": statement.loop_depth,
                    "variables": argument_names,
                    "codegen_preserves_arguments": policy.codegen_preserves_call_arguments,
                    "provenance": policy.provenance,
                })
        else:
            for name in argument_names:
                effective_uses[name].append(statement.order)

    lifetimes: list[_Lifetime] = []
    for name in local_types:
        events = definitions[name] + effective_uses[name]
        if not events:
            continue
        first_order = min(events)
        last_order = max(events)
        lifetimes.append(_Lifetime(
            name=name,
            type_name=local_types[name],
            declaration_index=declaration_index[name],
            first_order=first_order,
            last_order=last_order,
            definition_orders=tuple(definitions[name]),
            effective_use_orders=tuple(effective_uses[name]),
            omitted_use_orders=tuple(omitted_uses[name]),
        ))

    lifetimes.sort(key=lambda item: (item.first_order, item.declaration_index, item.name))

    assignments: list[dict[str, Any]] = []
    slot_end: list[int] = []
    slot_owner: list[str] = []
    slot_owner_type: list[str] = []
    reuse_relations: list[dict[str, Any]] = []

    if policy.slot_allocator == "first_fit_nonoverlap":
        for lifetime in lifetimes:
            slot = None
            for index, end in enumerate(slot_end):
                if end < lifetime.first_order:
                    slot = index
                    break
            if slot is None:
                slot = len(slot_end)
                slot_end.append(lifetime.last_order)
                slot_owner.append(lifetime.name)
                slot_owner_type.append(lifetime.type_name)
            else:
                previous_name = slot_owner[slot]
                previous_type = slot_owner_type[slot]
                reuse_relations.append({
                    "kind": "slot_reuse",
                    "function": function.name,
                    "slot": slot,
                    "from_variable": previous_name,
                    "from_type": previous_type,
                    "to_variable": lifetime.name,
                    "to_type": lifetime.type_name,
                    "cross_type": previous_type != lifetime.type_name,
                    "provenance": policy.provenance,
                })
                slot_end[slot] = lifetime.last_order
                slot_owner[slot] = lifetime.name
                slot_owner_type[slot] = lifetime.type_name
            assignments.append({
                "variable": lifetime.name,
                "type_name": lifetime.type_name,
                "slot": slot,
                "first_order": lifetime.first_order,
                "last_order": lifetime.last_order,
                "provenance": policy.provenance,
            })

    return {
        "function": function.name,
        "lifetimes": [item.to_dict() for item in lifetimes],
        "liveness_omissions": omissions,
        "slot_assignments": assignments,
        "slot_reuse_relations": reuse_relations,
    }


def analyze_embedded_compiler_semantics(
    program: EmbeddedProgram,
    policy: EmbeddedCompilerPolicy,
) -> dict[str, Any]:
    """Apply one explicit reviewed compiler policy to embedded source structure.

    The result proves only what follows from the supplied policy plus the parsed
    program.  It does not claim runtime execution, memory corruption, arbitrary
    write, GOT control or exploit success.
    """
    policy.validate()
    return_types = _function_return_types(program)
    functions = [
        _analyze_function(function, return_types, policy)
        for function in program.functions
        if function.locals
    ]
    return {
        "policy": policy.to_dict(),
        "functions": functions,
        "provenance": "EMBEDDED_STRUCTURE_PLUS_REVIEWED_COMPILER_POLICY",
        "limitations": [
            "slot reuse is compiler-policy derived, not runtime-observed",
            "cross-type slot reuse alone does not prove that the reused value is consumed under the old type",
            "memory corruption and exploitability require additional target semantics",
        ],
    }
