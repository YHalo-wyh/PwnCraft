"""Artifact-reviewed transport from stored user content to a format sink.

This layer composes an already-proven exact format write plan with a small,
exact instruction slice from the target ELF.  It proves only that user content
stored at a reviewed record offset can flow through a reviewed copy into the
first argument of a printf-like formatter.

It deliberately does not claim that the format plan executed, that a GOT write
completed, or that a later rebound call target was invoked.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any

from pwncraft.core.elf_artifact_provider import ElfArtifactSnapshot, ElfInstructionEvidence


@dataclass(frozen=True)
class ReviewedFormatSinkPathPolicy:
    name: str
    artifact_sha256: str
    record_content_offset: int
    put_record_load_address: int
    put_content_add_address: int
    put_destination_store_address: int
    put_input_call_address: int
    input_helper_address: int
    input_destination_load_address: int
    input_destination_add_address: int
    input_fread_argument_store_address: int
    input_fread_call_address: int
    fread_plt_address: int
    get_record_load_address: int
    get_content_add_address: int
    get_copy_source_store_address: int
    get_local_buffer_lea_address: int
    get_copy_destination_store_address: int
    get_strcpy_call_address: int
    strcpy_plt_address: int
    sink_local_buffer_lea_address: int
    sink_format_argument_store_address: int
    sink_printf_call_address: int
    printf_plt_address: int
    record_register: str = "eax"
    frame_register: str = "ebp"
    input_destination_register: str = "edx"
    input_index_register: str = "ecx"
    stack_pointer_register: str = "esp"
    local_buffer_displacement: int = -0xFC
    input_destination_argument_offset: int = 0x8
    provenance: str = "REVIEWED_FORMAT_SINK_PATH_POLICY"

    def validate(self) -> None:
        if not self.name.strip() or not re.fullmatch(r"[0-9a-fA-F]{64}", self.artifact_sha256):
            raise ValueError("format sink policy identity/artifact SHA are required")
        numeric = (
            self.record_content_offset,
            self.put_record_load_address,
            self.put_content_add_address,
            self.put_destination_store_address,
            self.put_input_call_address,
            self.input_helper_address,
            self.input_destination_load_address,
            self.input_destination_add_address,
            self.input_fread_argument_store_address,
            self.input_fread_call_address,
            self.fread_plt_address,
            self.get_record_load_address,
            self.get_content_add_address,
            self.get_copy_source_store_address,
            self.get_local_buffer_lea_address,
            self.get_copy_destination_store_address,
            self.get_strcpy_call_address,
            self.strcpy_plt_address,
            self.sink_local_buffer_lea_address,
            self.sink_format_argument_store_address,
            self.sink_printf_call_address,
            self.printf_plt_address,
            self.input_destination_argument_offset,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("format sink addresses/offsets must be non-negative")
        if self.local_buffer_displacement >= 0:
            raise ValueError("reviewed local buffer displacement must be stack-local/negative")
        for register in (
            self.record_register,
            self.frame_register,
            self.input_destination_register,
            self.input_index_register,
            self.stack_pointer_register,
        ):
            if not register.strip():
                raise ValueError("format sink register identities must be explicit")


def _instruction(snapshot: ElfArtifactSnapshot, address: int) -> ElfInstructionEvidence | None:
    matches = [item for item in snapshot.instructions if item.address == address]
    return matches[0] if len(matches) == 1 else None


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", str(text).lower()).replace("dwordptr", "").replace("qwordptr", "")


def _is_mnemonic(item: ElfInstructionEvidence | None, mnemonic: str) -> bool:
    return item is not None and item.mnemonic.lower() == mnemonic.lower()


def _call_target(item: ElfInstructionEvidence | None, target: int) -> bool:
    if item is None or item.mnemonic.lower() != "call":
        return False
    match = re.search(r"(?:0x)?([0-9a-f]+)", item.operands.lower())
    return match is not None and int(match.group(1), 16) == target


def _mov_from_frame(item: ElfInstructionEvidence | None, *, destination: str, frame: str, displacement: int) -> bool:
    if not _is_mnemonic(item, "mov"):
        return False
    operand = _norm(item.operands)
    if displacement < 0:
        intel_mem = f"[{frame.lower()}-{abs(displacement):#x}]"
        att_mem = f"-{abs(displacement):#x}(%{frame.lower()})"
    else:
        intel_mem = f"[{frame.lower()}+{displacement:#x}]"
        att_mem = f"{displacement:#x}(%{frame.lower()})"
    return operand in {
        f"{destination.lower()},{intel_mem}",
        f"{att_mem},%{destination.lower()}",
    }


def _lea_local(item: ElfInstructionEvidence | None, *, destination: str, frame: str, displacement: int) -> bool:
    if not _is_mnemonic(item, "lea"):
        return False
    operand = _norm(item.operands)
    intel = f"{destination.lower()},[{frame.lower()}-{abs(displacement):#x}]"
    att = f"-{abs(displacement):#x}(%{frame.lower()}),%{destination.lower()}"
    return operand in {intel, att}


def _add_immediate(item: ElfInstructionEvidence | None, *, register: str, value: int) -> bool:
    if not _is_mnemonic(item, "add"):
        return False
    operand = _norm(item.operands)
    return operand in {
        f"{register.lower()},{value:#x}",
        f"${value:#x},%{register.lower()}",
    }


def _add_register(item: ElfInstructionEvidence | None, *, destination: str, source: str) -> bool:
    if not _is_mnemonic(item, "add"):
        return False
    operand = _norm(item.operands)
    return operand in {
        f"{destination.lower()},{source.lower()}",
        f"%{source.lower()},%{destination.lower()}",
    }


def _stack_store(item: ElfInstructionEvidence | None, *, source: str, stack: str, offset: int) -> bool:
    if not _is_mnemonic(item, "mov"):
        return False
    operand = _norm(item.operands)
    if offset == 0:
        intel_mem = f"[{stack.lower()}]"
        att_mem = f"(%{stack.lower()})"
    else:
        intel_mem = f"[{stack.lower()}+{offset:#x}]"
        att_mem = f"{offset:#x}(%{stack.lower()})"
    return operand in {
        f"{intel_mem},{source.lower()}",
        f"%{source.lower()},{att_mem}",
    }


def _exact_plan_main_sha(upstream: dict[str, Any]) -> str | None:
    if "elf_bound_exact_format_got_rebind_plan" not in (upstream.get("capabilities") or []):
        return None
    artifacts = upstream.get("artifacts") or {}
    value = artifacts.get("main_sha256") if isinstance(artifacts, dict) else None
    return str(value).lower() if isinstance(value, str) else None


def derive_reviewed_format_sink_path(
    exact_plan_upstream: dict[str, Any],
    artifact: ElfArtifactSnapshot,
    policy: ReviewedFormatSinkPathPolicy,
) -> dict[str, Any] | None:
    """Prove stored user content reaches the first argument of the formatter."""
    policy.validate()
    if artifact.degraded or artifact.artifact_sha256.lower() != policy.artifact_sha256.lower():
        return None
    if _exact_plan_main_sha(exact_plan_upstream) != artifact.artifact_sha256.lower():
        return None

    ins = lambda address: _instruction(artifact, address)

    # put_file: record pointer -> record+content_offset -> get_input(destination).
    if not _mov_from_frame(
        ins(policy.put_record_load_address),
        destination=policy.record_register,
        frame=policy.frame_register,
        displacement=-0xC,
    ):
        return None
    if not _add_immediate(
        ins(policy.put_content_add_address), register=policy.record_register, value=policy.record_content_offset
    ):
        return None
    if not _stack_store(
        ins(policy.put_destination_store_address),
        source=policy.record_register,
        stack=policy.stack_pointer_register,
        offset=0,
    ):
        return None
    if not _call_target(ins(policy.put_input_call_address), policy.input_helper_address):
        return None

    # get_input: its first argument becomes the fread destination (+ loop index).
    if not _mov_from_frame(
        ins(policy.input_destination_load_address),
        destination=policy.input_destination_register,
        frame=policy.frame_register,
        displacement=policy.input_destination_argument_offset,
    ):
        return None
    if not _add_register(
        ins(policy.input_destination_add_address),
        destination=policy.input_destination_register,
        source=policy.input_index_register,
    ):
        return None
    if not _stack_store(
        ins(policy.input_fread_argument_store_address),
        source=policy.input_destination_register,
        stack=policy.stack_pointer_register,
        offset=0,
    ):
        return None
    if not _call_target(ins(policy.input_fread_call_address), policy.fread_plt_address):
        return None

    # get_file: exact record+content_offset is copied into one local buffer.
    if not _mov_from_frame(
        ins(policy.get_record_load_address),
        destination=policy.record_register,
        frame=policy.frame_register,
        displacement=-0xC,
    ):
        return None
    if not _add_immediate(
        ins(policy.get_content_add_address), register=policy.record_register, value=policy.record_content_offset
    ):
        return None
    if not _stack_store(
        ins(policy.get_copy_source_store_address),
        source=policy.record_register,
        stack=policy.stack_pointer_register,
        offset=4,
    ):
        return None
    if not _lea_local(
        ins(policy.get_local_buffer_lea_address),
        destination=policy.record_register,
        frame=policy.frame_register,
        displacement=policy.local_buffer_displacement,
    ):
        return None
    if not _stack_store(
        ins(policy.get_copy_destination_store_address),
        source=policy.record_register,
        stack=policy.stack_pointer_register,
        offset=0,
    ):
        return None
    if not _call_target(ins(policy.get_strcpy_call_address), policy.strcpy_plt_address):
        return None

    # The same local buffer is then passed as printf's first/format argument.
    if not _lea_local(
        ins(policy.sink_local_buffer_lea_address),
        destination=policy.record_register,
        frame=policy.frame_register,
        displacement=policy.local_buffer_displacement,
    ):
        return None
    if not _stack_store(
        ins(policy.sink_format_argument_store_address),
        source=policy.record_register,
        stack=policy.stack_pointer_register,
        offset=0,
    ):
        return None
    if not _call_target(ins(policy.sink_printf_call_address), policy.printf_plt_address):
        return None

    return {
        "kind": "reviewed_format_sink_path",
        "state": "derived_artifact_bound",
        "runtime_observed": False,
        "artifact": {
            "sha256": artifact.artifact_sha256,
            "name": artifact.artifact_name,
            "provider": artifact.provider,
        },
        "policy": asdict(policy),
        "facts": [
            {
                "kind": "reviewed_user_content_stored_at_record_offset",
                "record_content_offset": policy.record_content_offset,
                "input_call_address": policy.put_input_call_address,
                "input_helper_address": policy.input_helper_address,
            },
            {
                "kind": "reviewed_record_content_copied_to_local_buffer",
                "record_content_offset": policy.record_content_offset,
                "copy_call_address": policy.get_strcpy_call_address,
                "local_buffer_displacement": policy.local_buffer_displacement,
            },
            {
                "kind": "reviewed_local_buffer_is_printf_format_argument",
                "format_call_address": policy.sink_printf_call_address,
                "printf_plt_address": policy.printf_plt_address,
                "local_buffer_displacement": policy.local_buffer_displacement,
            },
            {
                "kind": "reviewed_format_plan_reaches_sink_conditionally",
                "requires_matching_record_selection": True,
                "format_plan_capability": "elf_bound_exact_format_got_rebind_plan",
            },
        ],
        "capabilities": ["reviewed_format_payload_sink_reachable"],
        "provenance": policy.provenance,
        "limitations": [
            "reachability is conditional on the requested record being selected by the target's lookup logic",
            "this proves transport into the formatter, not that every planned write atom executes successfully",
            "the actual GOT state after formatting remains a separate runtime/write-execution fact",
            "no rebound puts call-site, system invocation, shell or flag retrieval is inferred",
        ],
    }
