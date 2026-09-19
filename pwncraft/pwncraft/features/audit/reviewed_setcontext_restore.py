"""Artifact-reviewed setcontext restore semantics.

This layer consumes a previously reviewed stdio wide-vtable dispatch and an
exact local ELF artifact snapshot.  It verifies the target setcontext symbol
and a small instruction window before describing how the target libc maps the
original dispatch argument to the restore frame.

The shadow-stack branch is intentionally kept explicit.  Proving the ordinary
``push continuation; ret`` path exists is not the same as proving the runtime
will take that path, and neither fact by itself proves a stack pivot or ROP.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any

from pwncraft.core.elf_artifact_provider import (
    ElfArtifactSnapshot,
    ElfInstructionEvidence,
    resolve_symbol,
)


@dataclass(frozen=True)
class ReviewedSetcontextRestorePolicy:
    name: str
    artifact_sha256: str
    libc_base: int
    file_object_address: int
    setcontext_symbol: str = "setcontext"
    dispatch_argument_register: str = "rdi"
    frame_register: str = "rdx"
    stack_pointer_register: str = "rsp"
    continuation_register: str = "rcx"
    rsp_frame_offset: int = 0xA0
    continuation_frame_offset: int = 0xA8
    preserve_argument_instruction_offset: int = 0x04
    restore_frame_register_instruction_offset: int = 0x20
    restore_rsp_instruction_offset: int = 0x3D
    shadow_stack_test_instruction_offset: int = 0x5F
    ordinary_path_branch_instruction_offset: int = 0x6B
    ordinary_path_target_offset: int = 0x126
    continuation_load_instruction_offset: int = 0x126
    continuation_push_instruction_offset: int = 0x12D
    continuation_return_instruction_offset: int = 0x14E
    dispatch_argument_is_file_object_reviewed: bool = False
    provenance: str = "REVIEWED_SETCONTEXT_ARTIFACT_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not self.setcontext_symbol.strip():
            raise ValueError("setcontext restore policy identity/symbol are required")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", self.artifact_sha256):
            raise ValueError("artifact_sha256 must be an exact 64-hex digest")
        if min(
            self.libc_base,
            self.file_object_address,
            self.rsp_frame_offset,
            self.continuation_frame_offset,
            self.preserve_argument_instruction_offset,
            self.restore_frame_register_instruction_offset,
            self.restore_rsp_instruction_offset,
            self.shadow_stack_test_instruction_offset,
            self.ordinary_path_branch_instruction_offset,
            self.ordinary_path_target_offset,
            self.continuation_load_instruction_offset,
            self.continuation_push_instruction_offset,
            self.continuation_return_instruction_offset,
        ) < 0:
            raise ValueError("setcontext restore addresses/offsets must be non-negative")
        for register in (
            self.dispatch_argument_register,
            self.frame_register,
            self.stack_pointer_register,
            self.continuation_register,
        ):
            if not register.strip():
                raise ValueError("setcontext restore register names must be explicit")


def _dispatch_target(upstream: dict[str, Any], symbol: str) -> int | None:
    capabilities = set(upstream.get("capabilities") or [])
    if not {
        "reviewed_wide_vtable_dispatch_target",
        "reviewed_stdio_dispatch_target_reachable",
    }.issubset(capabilities):
        return None
    for fact in upstream.get("facts") or []:
        if not isinstance(fact, dict) or fact.get("kind") != "reviewed_wide_dispatch_target":
            continue
        if str(fact.get("target_symbol") or "") != symbol:
            return None
        value = fact.get("target_address")
        return int(value) if isinstance(value, int) else None
    return None


def _file_fields(upstream: dict[str, Any], file_object: int) -> dict[str, dict[str, Any]] | None:
    capabilities = set(upstream.get("capabilities") or [])
    if "reviewed_stdio_path_reachable" not in capabilities:
        return None
    for fact in upstream.get("facts") or []:
        if not isinstance(fact, dict) or fact.get("kind") != "reviewed_file_field_state":
            continue
        if fact.get("file_object_address") != file_object:
            return None
        fields = fact.get("fields") or []
        return {
            str(item.get("role")): item
            for item in fields
            if isinstance(item, dict) and str(item.get("role") or "")
        }
    return None


def _instruction_at(snapshot: ElfArtifactSnapshot, address: int) -> ElfInstructionEvidence | None:
    matches = [item for item in snapshot.instructions if item.address == address]
    return matches[0] if len(matches) == 1 else None


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", str(text).lower())


def _register_operand(instruction: ElfInstructionEvidence | None, mnemonic: str, register: str) -> bool:
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        return False
    operand = _norm(instruction.operands)
    return operand in {f"%{register.lower()}", register.lower()}


def _memory_load(
    instruction: ElfInstructionEvidence | None,
    *,
    base: str,
    offset: int,
    destination: str,
) -> bool:
    if instruction is None or instruction.mnemonic.lower() != "mov":
        return False
    operand = _norm(instruction.operands)
    att = f"{offset:#x}(%{base.lower()}),%{destination.lower()}"
    intel = f"{destination.lower()},qwordptr[{base.lower()}+{offset:#x}]"
    intel_plain = f"{destination.lower()},[{base.lower()}+{offset:#x}]"
    return operand in {att, intel, intel_plain}


def _shadow_stack_test(instruction: ElfInstructionEvidence | None) -> bool:
    if instruction is None or instruction.mnemonic.lower() not in {"test", "testl"}:
        return False
    operand = _norm(instruction.operands)
    return "0x2" in operand and "fs:0x48" in operand


def _branch_target(instruction: ElfInstructionEvidence | None, *, target: int) -> bool:
    if instruction is None or instruction.mnemonic.lower() not in {"je", "jz"}:
        return False
    text = instruction.operands.lower()
    match = re.search(r"(?:0x)?([0-9a-f]+)", text)
    return match is not None and int(match.group(1), 16) == target


def derive_reviewed_setcontext_restore(
    dispatch_upstream: dict[str, Any],
    stdio_upstream: dict[str, Any],
    libc: ElfArtifactSnapshot,
    policy: ReviewedSetcontextRestorePolicy,
) -> dict[str, Any] | None:
    """Derive target-libc frame semantics without asserting runtime pivoting."""
    policy.validate()
    if libc.degraded or libc.elf_type != "DYN":
        return None
    if libc.artifact_sha256.lower() != policy.artifact_sha256.lower():
        return None
    if not policy.dispatch_argument_is_file_object_reviewed:
        return None

    symbol = resolve_symbol(libc, policy.setcontext_symbol)
    if symbol is None:
        return None
    runtime_target = policy.libc_base + symbol.value
    if _dispatch_target(dispatch_upstream, policy.setcontext_symbol) != runtime_target:
        return None

    fields = _file_fields(stdio_upstream, policy.file_object_address)
    if fields is None:
        return None
    stack_field = fields.get("wide_data")
    continuation_field = fields.get("continuation")
    if stack_field is None or continuation_field is None:
        return None
    if stack_field.get("offset") != policy.rsp_frame_offset:
        return None
    if continuation_field.get("offset") != policy.continuation_frame_offset:
        return None
    restored_rsp = stack_field.get("value")
    restored_continuation = continuation_field.get("value")
    if not isinstance(restored_rsp, int) or not isinstance(restored_continuation, int):
        return None

    entry = symbol.value
    preserve = _instruction_at(libc, entry + policy.preserve_argument_instruction_offset)
    frame_pop = _instruction_at(libc, entry + policy.restore_frame_register_instruction_offset)
    rsp_load = _instruction_at(libc, entry + policy.restore_rsp_instruction_offset)
    shstk_test = _instruction_at(libc, entry + policy.shadow_stack_test_instruction_offset)
    ordinary_branch = _instruction_at(libc, entry + policy.ordinary_path_branch_instruction_offset)
    continuation_load = _instruction_at(libc, entry + policy.continuation_load_instruction_offset)
    continuation_push = _instruction_at(libc, entry + policy.continuation_push_instruction_offset)
    continuation_ret = _instruction_at(libc, entry + policy.continuation_return_instruction_offset)

    if not _register_operand(preserve, "push", policy.dispatch_argument_register):
        return None
    if not _register_operand(frame_pop, "pop", policy.frame_register):
        return None
    if not _memory_load(
        rsp_load,
        base=policy.frame_register,
        offset=policy.rsp_frame_offset,
        destination=policy.stack_pointer_register,
    ):
        return None
    if not _shadow_stack_test(shstk_test):
        return None
    ordinary_target = entry + policy.ordinary_path_target_offset
    if not _branch_target(ordinary_branch, target=ordinary_target):
        return None
    if not _memory_load(
        continuation_load,
        base=policy.frame_register,
        offset=policy.continuation_frame_offset,
        destination=policy.continuation_register,
    ):
        return None
    if not _register_operand(continuation_push, "push", policy.continuation_register):
        return None
    if continuation_ret is None or continuation_ret.mnemonic.lower() != "ret":
        return None

    return {
        "kind": "reviewed_setcontext_restore_semantics",
        "state": "derived_artifact_bound",
        "runtime_observed": False,
        "artifact": {
            "sha256": libc.artifact_sha256,
            "name": libc.artifact_name,
            "provider": libc.provider,
        },
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "setcontext_frame_base_from_original_dispatch_argument",
                "setcontext_offset": symbol.value,
                "argument_register": policy.dispatch_argument_register,
                "frame_register": policy.frame_register,
                "file_object_address": policy.file_object_address,
                "preserve_instruction_address": entry + policy.preserve_argument_instruction_offset,
                "restore_frame_register_instruction_address": entry + policy.restore_frame_register_instruction_offset,
            },
            {
                "kind": "setcontext_restores_rsp_from_frame",
                "instruction_address": entry + policy.restore_rsp_instruction_offset,
                "frame_offset": policy.rsp_frame_offset,
                "restored_rsp": restored_rsp,
            },
            {
                "kind": "setcontext_shadow_stack_runtime_branch",
                "test_instruction_address": entry + policy.shadow_stack_test_instruction_offset,
                "ordinary_branch_instruction_address": entry + policy.ordinary_path_branch_instruction_offset,
                "ordinary_path_target": ordinary_target,
                "runtime_path_resolved": False,
            },
            {
                "kind": "setcontext_ordinary_path_continuation_from_frame",
                "load_instruction_address": entry + policy.continuation_load_instruction_offset,
                "frame_offset": policy.continuation_frame_offset,
                "continuation": restored_continuation,
                "return_instruction_address": entry + policy.continuation_return_instruction_offset,
            },
            {
                "kind": "reviewed_setcontext_frame_values",
                "frame_address": policy.file_object_address,
                "rsp_field_address": policy.file_object_address + policy.rsp_frame_offset,
                "restored_rsp": restored_rsp,
                "continuation_field_address": policy.file_object_address + policy.continuation_frame_offset,
                "restored_continuation": restored_continuation,
            },
        ],
        "capabilities": [
            "reviewed_setcontext_frame_restore_semantics",
            "reviewed_setcontext_frame_values_bound",
        ],
        "provenance": policy.provenance,
        "limitations": [
            "the target libc contains both shadow-stack-aware and ordinary continuation paths",
            "this layer does not prove which setcontext shadow-stack branch the target process takes at runtime",
            "restored RSP and continuation values are frame semantics, not yet proof that ret-based gadgets execute",
            "no stack pivot, ROP/ORW execution, shell or flag retrieval is inferred here",
        ],
    }
