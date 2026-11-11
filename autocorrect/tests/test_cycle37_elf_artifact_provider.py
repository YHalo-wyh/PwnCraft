from pwncraft.core.elf_artifact_provider import (
    address_is_runtime_writable,
    relocations_for_symbol,
    resolve_symbol,
    runtime_symbol_address,
    snapshot_from_tool_outputs,
)


HEADER = """\
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


def test_cycle37_artifact_provider_binds_got_and_libc_symbols_without_name_guessing():
    main = snapshot_from_tool_outputs(
        artifact_sha256="11" * 32,
        artifact_name="pwn3",
        header_text=HEADER,
        symbols_text=MAIN_SYMBOLS,
        relocations_text=MAIN_RELOCS,
        program_headers_text=MAIN_PHDRS,
    )
    libc = snapshot_from_tool_outputs(
        artifact_sha256="22" * 32,
        artifact_name="libc.so",
        header_text=LIBC_HEADER,
        symbols_text=LIBC_SYMBOLS,
        relocations_text="",
        program_headers_text=LIBC_PHDRS,
    )

    puts_relocations = relocations_for_symbol(main, "puts")
    assert len(puts_relocations) == 1
    assert puts_relocations[0].offset == 0x0804A020
    assert address_is_runtime_writable(main, 0x0804A020) is True

    puts = resolve_symbol(libc, "puts")
    system = resolve_symbol(libc, "system")
    assert puts is not None and puts.value == 0x5F140
    assert system is not None and system.value == 0x3ADA0
    assert runtime_symbol_address(libc, "system", load_base=0xF7D00000) == 0xF7D3ADA0


def test_cycle37_relro_covered_target_is_not_promoted_writable():
    main = snapshot_from_tool_outputs(
        artifact_sha256="33" * 32,
        artifact_name="full-relro-like",
        header_text=HEADER,
        symbols_text=MAIN_SYMBOLS,
        relocations_text=MAIN_RELOCS.replace("0804a020", "0804a010"),
        program_headers_text=MAIN_PHDRS,
    )
    relocation = relocations_for_symbol(main, "puts")[0]
    assert relocation.offset == 0x0804A010
    assert address_is_runtime_writable(main, relocation.offset) is False
