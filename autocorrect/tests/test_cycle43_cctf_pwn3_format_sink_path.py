import json
from pathlib import Path

from pwncraft.core.elf_artifact_provider import snapshot_from_tool_outputs
from pwncraft.features.audit.reviewed_format_sink_path import (
    ReviewedFormatSinkPathPolicy,
    derive_reviewed_format_sink_path,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "fmtstr-pwn-linux-user-mode-fmtstr-2016-CCTF-pwn3-4fddf60b" / "expected_truth_cycle43.json"
PWN3_SHA256 = "4fddf60b4838794808fe865579aa6416f53ba40c030dde3854ee63957930bfa5"

HEADER = """\
ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Entry point address:               0x8048570
"""
PHDRS = """\
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x08048000 0x08048000 0x00e88 0x00e88 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00140 0x00184 RW  0x1000
"""
DISASSEMBLY = """\
08048777 <put_file>:
 80487bf: mov eax,DWORD PTR [ebp-0xc]
 80487c2: add eax,0x28
 80487d5: mov DWORD PTR [esp],eax
 80487d8: call 8048a19 <get_input>
080487f6 <get_file>:
 8048869: mov eax,DWORD PTR [ebp-0xc]
 804886c: add eax,0x28
 804886f: mov DWORD PTR [esp+0x4],eax
 8048873: lea eax,[ebp-0xfc]
 8048879: mov DWORD PTR [esp],eax
 804887c: call 80484f0 <strcpy@plt>
 8048895: lea eax,[ebp-0xfc]
 804889b: mov DWORD PTR [esp],eax
 804889e: call 80484c0 <printf@plt>
08048a19 <get_input>:
 8048a39: mov edx,DWORD PTR [ebp+0x8]
 8048a3c: add edx,ecx
 8048a52: mov DWORD PTR [esp],edx
 8048a55: call 80484e0 <fread@plt>
"""


def _snapshot(disassembly=DISASSEMBLY, sha256=PWN3_SHA256):
    return snapshot_from_tool_outputs(
        artifact_sha256=sha256,
        artifact_name="pwn3",
        header_text=HEADER,
        symbols_text="",
        relocations_text="",
        program_headers_text=PHDRS,
        disassembly_texts=[disassembly],
        provider="local-binutils",
    )


def _upstream(sha256=PWN3_SHA256):
    return {
        "capabilities": ["elf_bound_exact_format_got_rebind_plan"],
        "artifacts": {"main_sha256": sha256, "libc_sha256": "e5" * 32},
        "write_plan": {"kind": "exact_format_write_plan"},
    }


def _policy():
    rel = json.loads(TRUTH.read_text(encoding="utf-8"))["relative_policy"]
    return ReviewedFormatSinkPathPolicy(
        name="cctf-pwn3-record-content-to-printf",
        artifact_sha256=PWN3_SHA256,
        record_content_offset=rel["record_content_offset"],
        put_record_load_address=rel["put_record_load_address"],
        put_content_add_address=rel["put_content_add_address"],
        put_destination_store_address=rel["put_destination_store_address"],
        put_input_call_address=rel["put_input_call_address"],
        input_helper_address=rel["input_helper_address"],
        input_destination_load_address=rel["input_destination_load_address"],
        input_destination_add_address=rel["input_destination_add_address"],
        input_fread_argument_store_address=rel["input_fread_argument_store_address"],
        input_fread_call_address=rel["input_fread_call_address"],
        fread_plt_address=rel["fread_plt_address"],
        get_record_load_address=rel["get_record_load_address"],
        get_content_add_address=rel["get_content_add_address"],
        get_copy_source_store_address=rel["get_copy_source_store_address"],
        get_local_buffer_lea_address=rel["get_local_buffer_lea_address"],
        get_copy_destination_store_address=rel["get_copy_destination_store_address"],
        get_strcpy_call_address=rel["get_strcpy_call_address"],
        strcpy_plt_address=rel["strcpy_plt_address"],
        sink_local_buffer_lea_address=rel["sink_local_buffer_lea_address"],
        sink_format_argument_store_address=rel["sink_format_argument_store_address"],
        sink_printf_call_address=rel["sink_printf_call_address"],
        printf_plt_address=rel["printf_plt_address"],
        local_buffer_displacement=rel["local_buffer_displacement"],
        provenance="PINNED_CCTF_PWN3_OBJDUMP",
    )


def test_cycle43_exact_record_content_path_reaches_printf_format_argument():
    result = derive_reviewed_format_sink_path(_upstream(), _snapshot(), _policy())
    assert result is not None
    assert result["capabilities"] == ["reviewed_format_payload_sink_reachable"]
    facts = {fact["kind"]: fact for fact in result["facts"]}
    assert facts["reviewed_user_content_stored_at_record_offset"]["record_content_offset"] == 0x28
    assert facts["reviewed_record_content_copied_to_local_buffer"]["local_buffer_displacement"] == -0xFC
    assert facts["reviewed_local_buffer_is_printf_format_argument"]["format_call_address"] == 0x0804889E
    assert facts["reviewed_format_plan_reaches_sink_conditionally"]["requires_matching_record_selection"] is True
    joined = " ".join(result["capabilities"]).lower()
    assert "system" not in joined
    assert "shell" not in joined


def test_cycle43_wrong_artifact_or_plan_artifact_binding_stays_unknown():
    assert derive_reviewed_format_sink_path(
        _upstream(), _snapshot(sha256="ab" * 32), _policy()
    ) is None
    assert derive_reviewed_format_sink_path(
        _upstream(sha256="cd" * 32), _snapshot(), _policy()
    ) is None


def test_cycle43_wrong_record_content_offset_instruction_stays_unknown():
    bad = DISASSEMBLY.replace("80487c2: add eax,0x28", "80487c2: add eax,0x30")
    assert derive_reviewed_format_sink_path(_upstream(), _snapshot(bad), _policy()) is None


def test_cycle43_static_printf_format_instead_of_copied_local_buffer_stays_unknown():
    bad = DISASSEMBLY.replace(
        "804889b: mov DWORD PTR [esp],eax",
        "804889b: mov DWORD PTR [esp],0x8048b80",
    )
    assert derive_reviewed_format_sink_path(_upstream(), _snapshot(bad), _policy()) is None


def test_cycle43_copying_wrong_record_region_stays_unknown():
    bad = DISASSEMBLY.replace("804886c: add eax,0x28", "804886c: add eax,0x20")
    assert derive_reviewed_format_sink_path(_upstream(), _snapshot(bad), _policy()) is None
