from pwncraft.core.elf_artifact_provider import snapshot_from_tool_outputs
from pwncraft.features.audit.reviewed_format_elf_binding import (
    ElfFormatGotRebindPolicy,
    derive_elf_bound_format_got_rebind_plan,
)


MAIN_HEADER = """\
ELF Header:
  Class: ELF32
  Data: 2's complement, little endian
  Type: EXEC (Executable file)
  Machine: Intel 80386
  Entry point address: 0x80484c0
"""
MAIN_SYMBOLS = """\
Symbol table '.dynsym' contains 2 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.0
"""
MAIN_RELOCS = """\
Relocation section '.rel.plt' contains 1 entry:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a020  00000107 R_386_JUMP_SLOT 00000000   puts@GLIBC_2.0
"""
MAIN_PHDRS = """\
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x08048000 0x08048000 0x01000 0x01000 R E 0x1000
  LOAD           0x001000 0x0804a000 0x0804a000 0x01000 0x01000 RW  0x1000
  GNU_RELRO      0x001000 0x0804a000 0x0804a000 0x00020 0x00020 R   0x1
"""
LIBC_HEADER = """\
ELF Header:
  Class: ELF32
  Data: 2's complement, little endian
  Type: DYN (Shared object file)
  Machine: Intel 80386
  Entry point address: 0x18e30
"""
LIBC_SYMBOLS = """\
Symbol table '.dynsym' contains 3 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     1: 0005f140   432 FUNC    GLOBAL DEFAULT   13 puts@@GLIBC_2.0
     2: 0003ada0    55 FUNC    GLOBAL DEFAULT   13 system@@GLIBC_2.0
"""
LIBC_PHDRS = """\
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x000000 0x00000000 0x00000000 0x100000 0x100000 R E 0x1000
"""


def _main(*, relro_end=0x0804A020):
    phdrs = MAIN_PHDRS.replace("0x00020 0x00020", f"0x{relro_end - 0x0804A000:05x} 0x{relro_end - 0x0804A000:05x}")
    return snapshot_from_tool_outputs(
        artifact_sha256="41" * 32,
        artifact_name="pwn3",
        header_text=MAIN_HEADER,
        symbols_text=MAIN_SYMBOLS,
        relocations_text=MAIN_RELOCS,
        program_headers_text=phdrs,
    )


def _libc():
    return snapshot_from_tool_outputs(
        artifact_sha256="42" * 32,
        artifact_name="libc.so",
        header_text=LIBC_HEADER,
        symbols_text=LIBC_SYMBOLS,
        relocations_text="",
        program_headers_text=LIBC_PHDRS,
    )


def _policy(observed_puts=0xF7D5F140):
    return ElfFormatGotRebindPolicy(
        name="cctf-like-puts-to-system",
        target_import_name="puts",
        observed_libc_symbol="puts",
        desired_libc_symbol="system",
        observed_libc_symbol_address=observed_puts,
        first_pointer_argument=7,
        total_bits=32,
        atom_bits=16,
    )


def test_cycle38_exact_elf_and_runtime_evidence_produces_numeric_got_rebind_plan():
    result = derive_elf_bound_format_got_rebind_plan(_main(), _libc(), _policy())
    assert result is not None
    assert result["facts"][0]["runtime_address"] == 0x0804A020
    assert result["facts"][0]["runtime_writable"] is True
    assert result["facts"][1]["libc_base"] == 0xF7D00000
    assert result["facts"][2]["runtime_address"] == 0xF7D3ADA0
    assert result["write_plan"]["policy"]["target_address"] == 0x0804A020
    assert result["write_plan"]["policy"]["desired_value"] == 0xF7D3ADA0
    assert result["capabilities"] == ["elf_bound_exact_format_got_rebind_plan"]


def test_cycle38_relro_covered_got_stays_unknown():
    # Extend GNU_RELRO through 0x804a021 so the relocation byte is protected.
    main = _main(relro_end=0x0804A021)
    assert derive_elf_bound_format_got_rebind_plan(main, _libc(), _policy()) is None


def test_cycle38_missing_observed_symbol_or_wrong_libc_artifact_stays_unknown():
    libc = snapshot_from_tool_outputs(
        artifact_sha256="43" * 32,
        artifact_name="wrong-libc.so",
        header_text=LIBC_HEADER,
        symbols_text=LIBC_SYMBOLS.replace("puts@@GLIBC_2.0", "printf@@GLIBC_2.0"),
        relocations_text="",
        program_headers_text=LIBC_PHDRS,
    )
    assert derive_elf_bound_format_got_rebind_plan(_main(), libc, _policy()) is None


def test_cycle38_degraded_artifact_evidence_never_promotes_exact_plan():
    libc = snapshot_from_tool_outputs(
        artifact_sha256="44" * 32,
        artifact_name="degraded-libc.so",
        header_text=LIBC_HEADER,
        symbols_text=LIBC_SYMBOLS,
        relocations_text="",
        program_headers_text=LIBC_PHDRS,
        degraded=True,
        degrade_notes=["symbol table incomplete"],
    )
    assert derive_elf_bound_format_got_rebind_plan(_main(), libc, _policy()) is None
