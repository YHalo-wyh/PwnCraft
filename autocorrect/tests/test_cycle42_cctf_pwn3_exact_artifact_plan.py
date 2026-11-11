import json
from pathlib import Path

from pwncraft.core.elf_artifact_provider import snapshot_from_tool_outputs
from pwncraft.features.audit.reviewed_format_elf_binding import (
    ElfFormatGotRebindPolicy,
    derive_elf_bound_format_got_rebind_plan,
)

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "fmtstr-pwn-linux-user-mode-fmtstr-2016-CCTF-pwn3-4fddf60b" / "expected_truth_cycle42.json"

PWN3_SHA256 = "4fddf60b4838794808fe865579aa6416f53ba40c030dde3854ee63957930bfa5"
LIBC_SHA256 = "e57fa6bf382a5c8d20895a434317f3f6767e7f5b6485bc47970bd9a1cc5d471d"

MAIN_HEADER = """\
ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Entry point address:               0x8048570
"""
MAIN_SYMBOLS = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     8: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.0
"""
MAIN_RELOCS = """\
Relocation section '.rel.plt' at offset 0x400 contains 13 entries:
 Offset     Info    Type                Sym. Value  Symbol's Name
0804a028  00000807 R_386_JUMP_SLOT        00000000   puts@GLIBC_2.0
"""
MAIN_PHDRS = """\
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x08048000 0x08048000 0x00e88 0x00e88 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00140 0x00184 RW  0x1000
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1
"""

LIBC_HEADER = """\
ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              DYN (Shared object file)
  Machine:                           Intel 80386
  Entry point address:               0x18e30
"""
LIBC_SYMBOLS = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
   434: 0005fca0   464 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.0
  1457: 0003ada0    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
"""
LIBC_PHDRS = """\
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x00000000 0x00000000 0x100000 0x100000 R E 0x1000
"""


def _main(*, relro_size=0xF8):
    phdrs = MAIN_PHDRS.replace("0x000f8 0x000f8", f"0x{relro_size:05x} 0x{relro_size:05x}")
    return snapshot_from_tool_outputs(
        artifact_sha256=PWN3_SHA256,
        artifact_name="pwn3",
        header_text=MAIN_HEADER,
        symbols_text=MAIN_SYMBOLS,
        relocations_text=MAIN_RELOCS,
        program_headers_text=phdrs,
        provider="local-binutils",
    )


def _libc(symbols=LIBC_SYMBOLS):
    return snapshot_from_tool_outputs(
        artifact_sha256=LIBC_SHA256,
        artifact_name="libc.so",
        header_text=LIBC_HEADER,
        symbols_text=symbols,
        relocations_text="",
        program_headers_text=LIBC_PHDRS,
        provider="local-binutils",
    )


def _policy(observed_puts: int):
    truth = json.loads(TRUTH.read_text(encoding="utf-8"))
    rel = truth["relative_policy"]
    return ElfFormatGotRebindPolicy(
        name="cctf-pwn3-exact-puts-to-system",
        target_import_name="puts",
        observed_libc_symbol="puts",
        desired_libc_symbol="system",
        observed_libc_symbol_address=observed_puts,
        first_pointer_argument=rel["first_pointer_argument"],
        total_bits=rel["total_bits"],
        atom_bits=rel["atom_bits"],
        initial_count=rel["initial_count"],
        provenance="PINNED_CCTF_PWN3_ARTIFACTS_PLUS_RUNTIME_PUTS",
    )


def test_cycle42_exact_cctf_artifacts_plus_runtime_puts_produce_numeric_plan():
    base = 0xF7D00000
    observed_puts = base + 0x5FCA0
    result = derive_elf_bound_format_got_rebind_plan(_main(), _libc(), _policy(observed_puts))
    assert result is not None
    assert result["artifacts"] == {
        "main_sha256": PWN3_SHA256,
        "libc_sha256": LIBC_SHA256,
    }
    assert result["facts"][0]["runtime_address"] == 0x0804A028
    assert result["facts"][0]["runtime_writable"] is True
    assert result["facts"][1]["symbol_offset"] == 0x5FCA0
    assert result["facts"][1]["libc_base"] == base
    assert result["facts"][2]["symbol_offset"] == 0x3ADA0
    assert result["facts"][2]["runtime_address"] == base + 0x3ADA0
    assert result["write_plan"]["policy"]["target_address"] == 0x0804A028
    assert result["write_plan"]["policy"]["desired_value"] == base + 0x3ADA0
    assert result["write_plan"]["policy"]["first_pointer_argument"] == 7
    assert result["capabilities"] == ["elf_bound_exact_format_got_rebind_plan"]
    assert "shell" not in " ".join(result["capabilities"]).lower()


def test_cycle42_relro_covering_puts_got_blocks_plan():
    # GNU_RELRO starts at 0x8049f08. Size 0x121 makes the protected interval
    # extend through byte 0x804a028, so the exact puts relocation is not writable.
    main = _main(relro_size=0x121)
    base = 0xF7D00000
    assert derive_elf_bound_format_got_rebind_plan(
        main, _libc(), _policy(base + 0x5FCA0)
    ) is None


def test_cycle42_wrong_paired_libc_without_puts_definition_blocks_plan():
    symbols = LIBC_SYMBOLS.replace("puts@@GLIBC_2.0", "printf@@GLIBC_2.0")
    base = 0xF7D00000
    assert derive_elf_bound_format_got_rebind_plan(
        _main(), _libc(symbols), _policy(base + 0x5FCA0)
    ) is None


def test_cycle42_runtime_observation_is_not_replaced_by_static_magic_system_address():
    # No runtime puts observation is encoded in the artifacts themselves. A value
    # below the exact puts offset cannot yield a valid runtime libc base.
    assert derive_elf_bound_format_got_rebind_plan(
        _main(), _libc(), _policy(0x1000)
    ) is None
