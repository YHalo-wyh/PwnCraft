import json
from pathlib import Path

from pwncraft.core.elf_artifact_provider import snapshot_from_tool_outputs
from pwncraft.features.audit.reviewed_setcontext_restore import (
    ReviewedSetcontextRestorePolicy,
    derive_reviewed_setcontext_restore,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-ubw-1b3b161e" / "expected_truth_cycle41.json"

HEADER = """\
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x27490
"""

SYMBOLS = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
  2594: 000000000004a960   352 FUNC    WEAK   DEFAULT   17 setcontext@@GLIBC_2.2.5
"""

PROGRAM_HEADERS = """\
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x020000 0x020000 R   0x1000
  LOAD           0x020000 0x0000000000020000 0x0000000000020000 0x180000 0x180000 R E 0x1000
"""

DISASSEMBLY = """\
000000000004a960 <setcontext@@GLIBC_2.2.5>:
   4a964: push   %rdi
   4a980: pop    %rdx
   4a99d: mov    0xa0(%rdx),%rsp
   4a9bf: testl  $0x2,%fs:0x48
   4a9cb: je     4aa86 <setcontext@@GLIBC_2.2.5+0x126>
   4aa86: mov    0xa8(%rdx),%rcx
   4aa8d: push   %rcx
   4aaae: ret
"""

LIBC_SHA256 = "d8db8739a1633c972cec6a4fe0566bdcec6fd088f98723492ab0361f66238f75"


def _snapshot(disassembly: str = DISASSEMBLY, sha256: str = LIBC_SHA256):
    return snapshot_from_tool_outputs(
        artifact_sha256=sha256,
        artifact_name="libc.so.6",
        header_text=HEADER,
        symbols_text=SYMBOLS,
        relocations_text="",
        program_headers_text=PROGRAM_HEADERS,
        disassembly_texts=[disassembly],
        provider="local-binutils",
        tool_versions={"readelf": "GNU readelf", "objdump": "GNU objdump"},
    )


def _dispatch_upstream(libc_base: int):
    return {
        "capabilities": [
            "reviewed_wide_vtable_dispatch_target",
            "reviewed_stdio_dispatch_target_reachable",
        ],
        "facts": [
            {
                "kind": "reviewed_wide_dispatch_target",
                "target_address": libc_base + 0x4A960,
                "target_symbol": "setcontext",
            }
        ],
    }


def _stdio_upstream(file_object: int, widep: int, continuation: int):
    return {
        "capabilities": ["reviewed_stdio_path_reachable"],
        "facts": [
            {
                "kind": "reviewed_file_field_state",
                "file_object_address": file_object,
                "fields": [
                    {"role": "wide_data", "offset": 0xA0, "value": widep, "width": 8},
                    {"role": "continuation", "offset": 0xA8, "value": continuation, "width": 8},
                ],
            }
        ],
    }


def _policy(libc_base: int, file_object: int):
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    rel = truth["relative_policy"]
    return ReviewedSetcontextRestorePolicy(
        name="sctf-ubw-setcontext-restore",
        artifact_sha256=rel["artifact_sha256"],
        libc_base=libc_base,
        file_object_address=file_object,
        setcontext_symbol=rel["setcontext_symbol"],
        dispatch_argument_register=rel["dispatch_argument_register"],
        frame_register=rel["frame_register"],
        rsp_frame_offset=rel["rsp_frame_offset"],
        continuation_frame_offset=rel["continuation_frame_offset"],
        preserve_argument_instruction_offset=rel["preserve_argument_instruction_offset"],
        restore_frame_register_instruction_offset=rel["restore_frame_register_instruction_offset"],
        restore_rsp_instruction_offset=rel["restore_rsp_instruction_offset"],
        shadow_stack_test_instruction_offset=rel["shadow_stack_test_instruction_offset"],
        ordinary_path_branch_instruction_offset=rel["ordinary_path_branch_instruction_offset"],
        ordinary_path_target_offset=rel["ordinary_path_target_offset"],
        continuation_load_instruction_offset=rel["continuation_load_instruction_offset"],
        continuation_push_instruction_offset=rel["continuation_push_instruction_offset"],
        continuation_return_instruction_offset=rel["continuation_return_instruction_offset"],
        dispatch_argument_is_file_object_reviewed=True,
        provenance="PINNED_OFFICIAL_UBW_LIBC_AND_EXP",
    )


def test_cycle41_exact_target_libc_binds_frame_rsp_and_ordinary_continuation_without_pivot():
    libc = 0x7F0000000000
    fake_file = 0x555550005000
    widep = 0x555550006000
    continuation = libc + 0x12DFBA

    result = derive_reviewed_setcontext_restore(
        _dispatch_upstream(libc),
        _stdio_upstream(fake_file, widep, continuation),
        _snapshot(),
        _policy(libc, fake_file),
    )
    assert result is not None
    assert result["artifact"]["sha256"] == LIBC_SHA256
    assert result["capabilities"] == [
        "reviewed_setcontext_frame_restore_semantics",
        "reviewed_setcontext_frame_values_bound",
    ]

    facts = {fact["kind"]: fact for fact in result["facts"]}
    assert facts["setcontext_frame_base_from_original_dispatch_argument"]["argument_register"] == "rdi"
    assert facts["setcontext_frame_base_from_original_dispatch_argument"]["frame_register"] == "rdx"
    assert facts["setcontext_restores_rsp_from_frame"]["frame_offset"] == 0xA0
    assert facts["setcontext_restores_rsp_from_frame"]["restored_rsp"] == widep
    assert facts["setcontext_ordinary_path_continuation_from_frame"]["frame_offset"] == 0xA8
    assert facts["setcontext_ordinary_path_continuation_from_frame"]["continuation"] == continuation
    assert facts["setcontext_shadow_stack_runtime_branch"]["runtime_path_resolved"] is False

    caps = " ".join(result["capabilities"]).lower()
    assert "pivot" not in caps
    assert "rop" not in caps
    assert "shell" not in caps


def test_cycle41_wrong_libc_artifact_stays_unknown():
    libc = 0x7F0000000000
    fake_file = 0x555550005000
    policy = _policy(libc, fake_file)
    assert derive_reviewed_setcontext_restore(
        _dispatch_upstream(libc),
        _stdio_upstream(fake_file, 0x555550006000, libc + 0x12DFBA),
        _snapshot(sha256="ab" * 32),
        policy,
    ) is None


def test_cycle41_wrong_dispatch_target_stays_unknown():
    libc = 0x7F0000000000
    fake_file = 0x555550005000
    upstream = _dispatch_upstream(libc)
    upstream["facts"][0]["target_address"] += 1
    assert derive_reviewed_setcontext_restore(
        upstream,
        _stdio_upstream(fake_file, 0x555550006000, libc + 0x12DFBA),
        _snapshot(),
        _policy(libc, fake_file),
    ) is None


def test_cycle41_wrong_rsp_restore_instruction_stays_unknown():
    libc = 0x7F0000000000
    fake_file = 0x555550005000
    bad_disassembly = DISASSEMBLY.replace("mov    0xa0(%rdx),%rsp", "mov    0xb0(%rdx),%rsp")
    assert derive_reviewed_setcontext_restore(
        _dispatch_upstream(libc),
        _stdio_upstream(fake_file, 0x555550006000, libc + 0x12DFBA),
        _snapshot(disassembly=bad_disassembly),
        _policy(libc, fake_file),
    ) is None


def test_cycle41_missing_continuation_field_stays_unknown():
    libc = 0x7F0000000000
    fake_file = 0x555550005000
    stdio = _stdio_upstream(fake_file, 0x555550006000, libc + 0x12DFBA)
    stdio["facts"][0]["fields"] = [
        field for field in stdio["facts"][0]["fields"] if field["role"] != "continuation"
    ]
    assert derive_reviewed_setcontext_restore(
        _dispatch_upstream(libc),
        stdio,
        _snapshot(),
        _policy(libc, fake_file),
    ) is None


def test_cycle41_unreviewed_dispatch_argument_identity_stays_unknown():
    libc = 0x7F0000000000
    fake_file = 0x555550005000
    policy = _policy(libc, fake_file)
    policy = ReviewedSetcontextRestorePolicy(
        **{**policy.__dict__, "dispatch_argument_is_file_object_reviewed": False}
    )
    assert derive_reviewed_setcontext_restore(
        _dispatch_upstream(libc),
        _stdio_upstream(fake_file, 0x555550006000, libc + 0x12DFBA),
        _snapshot(),
        policy,
    ) is None


def test_cycle41_wrong_ordinary_shadow_stack_branch_target_stays_unknown():
    libc = 0x7F0000000000
    fake_file = 0x555550005000
    bad_disassembly = DISASSEMBLY.replace(
        "je     4aa86 <setcontext@@GLIBC_2.2.5+0x126>",
        "je     4aa80 <setcontext@@GLIBC_2.2.5+0x120>",
    )
    assert derive_reviewed_setcontext_restore(
        _dispatch_upstream(libc),
        _stdio_upstream(fake_file, 0x555550006000, libc + 0x12DFBA),
        _snapshot(disassembly=bad_disassembly),
        _policy(libc, fake_file),
    ) is None
