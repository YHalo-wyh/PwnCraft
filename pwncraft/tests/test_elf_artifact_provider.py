from pathlib import Path
import shutil

import pytest

from pwncraft.core.elf_artifact_provider import (
    SCHEMA_VERSION,
    address_is_executable,
    address_is_runtime_writable,
    collect_elf_artifact_snapshot,
    instruction_window,
    load_elf_artifact_snapshot,
    relocation_runtime_address,
    relocations_for_symbol,
    resolve_symbol,
    runtime_symbol_address,
    snapshot_from_tool_outputs,
)


HEADER = """\
ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x27490
"""

SYMBOLS = """\
Symbol table '.dynsym' contains 4 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000052290    45 FUNC    GLOBAL DEFAULT   16 system@@GLIBC_2.2.5
     2: 000000000004a960   180 FUNC    GLOBAL DEFAULT   16 setcontext@@GLIBC_2.2.5
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5
"""

RELOCATIONS = """\
Relocation section '.rela.plt' at offset 0x1000 contains 1 entry:
    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
0000000000404018  000300000007 R_X86_64_JUMP_SLOT 0000000000000000 puts@GLIBC_2.2.5 + 0
"""

PROGRAM_HEADERS = """\
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x001000 0x001000 R   0x1000
  LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x080000 0x080000 R E 0x1000
  LOAD           0x090000 0x0000000000403000 0x0000000000403000 0x002000 0x002000 RW  0x1000
  GNU_RELRO      0x090df0 0x0000000000403df0 0x0000000000403df0 0x000210 0x000210 R   0x1
"""

DISASSEMBLY = """\
000000000004a960 <setcontext@@GLIBC_2.2.5>:
   4a960: mov    0xa0(%rdx),%rsp
   4a967: mov    0x80(%rdx),%rbx
   4a96e: push   0xa8(%rdx)
   4a974: ret
"""


def _snapshot():
    return snapshot_from_tool_outputs(
        artifact_sha256="cd" * 32,
        artifact_name="libc.so.6",
        header_text=HEADER,
        symbols_text=SYMBOLS,
        relocations_text=RELOCATIONS,
        program_headers_text=PROGRAM_HEADERS,
        disassembly_texts=[DISASSEMBLY],
        tool_versions={"readelf": "GNU readelf 2.42", "objdump": "GNU objdump 2.42"},
    )


def test_elf_artifact_snapshot_resolves_versioned_symbols_without_magic_offsets():
    snapshot = _snapshot()
    system = resolve_symbol(snapshot, "system")
    setcontext = resolve_symbol(snapshot, "setcontext@@GLIBC_2.2.5")
    assert system is not None and system.value == 0x52290
    assert setcontext is not None and setcontext.value == 0x4A960
    assert runtime_symbol_address(snapshot, "system", load_base=0x7F0000000000) == 0x7F0000052290
    assert resolve_symbol(snapshot, "puts") is None  # undefined import is not a definition


def test_elf_artifact_snapshot_binds_relocation_and_runtime_writability():
    snapshot = _snapshot()
    relocs = relocations_for_symbol(snapshot, "puts")
    assert len(relocs) == 1
    relocation = relocs[0]
    assert relocation.offset == 0x404018
    assert relocation_runtime_address(snapshot, relocation, load_base=0x555550000000) == 0x555550404018
    # 0x404018 lies in RW LOAD but outside the GNU_RELRO range ending at 0x404000.
    assert address_is_runtime_writable(snapshot, 0x404018) is True
    assert address_is_runtime_writable(snapshot, 0x403FF0) is False
    assert address_is_executable(snapshot, 0x4A960) is True


def test_elf_artifact_snapshot_keeps_bounded_instruction_evidence():
    snapshot = _snapshot()
    instructions = instruction_window(snapshot, 0x4A960, 0x4A975)
    assert [item.mnemonic for item in instructions] == ["mov", "mov", "push", "ret"]
    assert instructions[0].operands == "0xa0(%rdx),%rsp"
    assert instructions[0].function_name == "setcontext@@GLIBC_2.2.5"


def test_elf_artifact_snapshot_round_trips_through_strict_loader():
    original = _snapshot()
    restored = load_elf_artifact_snapshot(original.to_dict())
    assert restored.schema_version == SCHEMA_VERSION
    assert restored.artifact_sha256 == "cd" * 32
    assert resolve_symbol(restored, "system").value == 0x52290
    assert instruction_window(restored, 0x4A960, 0x4A968)[0].address == 0x4A960


def test_elf_artifact_snapshot_rejects_untrusted_shape():
    payload = _snapshot().to_dict()
    payload["artifact_sha256"] = "not-a-digest"
    with pytest.raises(ValueError):
        load_elf_artifact_snapshot(payload)

    payload = _snapshot().to_dict()
    payload["memory_ranges"][0]["end"] = -1
    with pytest.raises(ValueError):
        load_elf_artifact_snapshot(payload)


def test_local_binutils_collector_smoke_when_available():
    fixture = Path("/bin/true")
    if not fixture.is_file() or shutil.which("readelf") is None:
        pytest.skip("local ELF/binutils fixture unavailable")
    snapshot = collect_elf_artifact_snapshot(fixture)
    assert snapshot.artifact_name == "true"
    assert len(snapshot.artifact_sha256) == 64
    assert any(item.kind == "LOAD" for item in snapshot.memory_ranges)
    assert snapshot.provider == "local-binutils"
