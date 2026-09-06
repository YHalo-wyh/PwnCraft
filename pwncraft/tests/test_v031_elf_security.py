"""v0.31 tests: local ELF security parsing (no WSL checksec dependency).

``parse_elf_security`` reads protections straight from the ELF bytes so the
import path never depends on a ``checksec`` tool being installed in WSL.
These tests construct minimal ELFs byte-by-byte to pin each protection bit.
"""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from pwncraft.core.workbench import parse_elf_security


def _build_elf(
    *,
    is64: bool = True,
    e_type: int = 2,  # ET_EXEC
    gnu_stack_exec: bool = False,
    gnu_stack_present: bool = True,
    gnu_relro: bool = False,
    bind_now: bool = False,
    dynsym_names: tuple[bytes, ...] = (),
    with_symtab: bool = False,
) -> bytes:
    endian = "<"
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    shentsize = 64 if is64 else 40
    sym_entsize = 24 if is64 else 16
    dyn_entsize = 16 if is64 else 8

    program: list[tuple] = []
    phnum = 0
    if gnu_stack_present:
        flags = 0x6 | (0x1 if gnu_stack_exec else 0)
        program.append((0x6474E551, flags, 0, 0, 0, 0))
        phnum += 1
    if gnu_relro:
        program.append((0x6474E552, 0x4, 0, 0, 0, 0))
        phnum += 1

    dyn_entries: list[tuple[int, int]] = []
    if bind_now:
        dyn_entries.append((30, 0x8))  # DT_FLAGS / BIND_NOW
    if dyn_entries:
        dyn_entries.append((0, 0))
        program.append((2, 0x4, 0, 0, 0, 0))  # PT_DYNAMIC 占位，偏移稍后回填
        phnum += 1

    # 绝对文件偏移布局（phnum 已含 DYNAMIC 槽位）
    strtab = b"\x00" + b"".join(name + b"\x00" for name in dynsym_names)
    dyn_off = ehsize + phentsize * phnum
    dyn_size = len(dyn_entries) * dyn_entsize
    if dyn_entries:
        program[-1] = (2, 0x4, dyn_off, dyn_off, dyn_size, 0)
    sym_off = dyn_off + dyn_size
    symtab_blob = b"\x00" * sym_entsize + b"".join(
        (struct.pack("<IBBHQQ", strtab.find(name), 0x12, 0, 0, 0, 0) if is64
         else struct.pack("<IIIBBH", strtab.find(name), 0, 0, 0x12, 0, 0))
        for name in dynsym_names
    )
    strtab_off = sym_off + len(symtab_blob)
    shstrtab = b"\x00.symtab\x00.dynsym\x00.dynstr\x00"
    shstrtab_off = strtab_off + len(strtab)

    sections: list[tuple[int, int, int, int, int]] = []  # name,type,offset,size,link(+entsize 单独)
    sec_rows: list[tuple[int, int, int, int, int, int]] = [(0, 0, 0, 0, 0, 0)]
    if dynsym_names:
        sec_rows.append((1, 11, sym_off, len(symtab_blob), 2, sym_entsize))       # .dynsym → dynstr
        sec_rows.append((9, 3, strtab_off, len(strtab), 0, 0))                    # .dynstr
    if with_symtab:
        sec_rows.append((17, 2, sym_off, sym_entsize, 0, sym_entsize))            # .symtab
    shoff = shstrtab_off + len(shstrtab)

    if is64:
        header = (b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
                  + struct.pack("<HHIQQQIHHHHHH", e_type, 0x3E, 1, 0x1000, ehsize, shoff,
                                0, ehsize, phentsize, phnum, shentsize, len(sec_rows), 0))
    else:
        header = (b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
                  + struct.pack("<HHIIIIIHHHHHH", e_type, 0x03, 1, 0x1000, ehsize, shoff,
                                0, ehsize, phentsize, phnum, shentsize, len(sec_rows), 0))

    blob = bytearray(header)
    def ensure(end: int) -> None:
        if len(blob) < end:
            blob.extend(b"\x00" * (end - len(blob)))

    for index, entry in enumerate(program):
        p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz = entry
        base = ehsize + index * phentsize
        ensure(base + phentsize)
        if is64:
            struct.pack_into("<IIQQQQQQ", blob, base, p_type, p_flags, p_offset, p_vaddr, p_vaddr, p_filesz, p_memsz, 0x10)
        else:
            struct.pack_into("<IIIIIIII", blob, base, p_type, p_offset, p_vaddr, p_vaddr, p_filesz, p_memsz, p_flags, 0x10)
    for index, (tag, value) in enumerate(dyn_entries):
        base = dyn_off + index * dyn_entsize
        ensure(base + dyn_entsize)
        if is64:
            struct.pack_into("<QQ", blob, base, tag, value)
        else:
            struct.pack_into("<II", blob, base, tag, value)
    ensure(strtab_off + len(strtab))
    blob[sym_off:sym_off + len(symtab_blob)] = symtab_blob
    blob[strtab_off:strtab_off + len(strtab)] = strtab
    ensure(shstrtab_off + len(shstrtab))
    blob[shstrtab_off:shstrtab_off + len(shstrtab)] = shstrtab
    ensure(shoff)
    for row in sec_rows:
        name, s_type, s_off, s_size, s_link, s_entsize = row
        if is64:
            blob += struct.pack("<IIQQQQIIQQ", name, s_type, 0, 0, s_off, s_size, s_link, 0, 0, s_entsize)
        else:
            blob += struct.pack("<IIIIIIIIII", name, s_type, 0, 0, s_off, s_size, s_link, 0, 0, s_entsize)
    return bytes(blob)


class ElfSecurityParsingTests(unittest.TestCase):
    def _parse(self, blob: bytes) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pwn"
            path.write_bytes(blob)
            return parse_elf_security(path)

    def test_naked_exec_no_gnu_stack(self) -> None:
        security = self._parse(_build_elf(gnu_stack_present=False))
        self.assertEqual(security["PIE"], "OFF")
        self.assertEqual(security["NX"], "OFF")  # GNU_STACK 缺省 = NX 关闭
        self.assertEqual(security["RELRO"], "NONE")
        self.assertEqual(security["CANARY"], "OFF")
        self.assertEqual(security["STRIPPED"], "ON")  # 无节表

    def test_exec_with_execstack_is_nx_off(self) -> None:
        security = self._parse(_build_elf(gnu_stack_exec=True))
        self.assertEqual(security["PIE"], "OFF")
        self.assertEqual(security["NX"], "OFF")
        self.assertEqual(security["RELRO"], "NONE")

    def test_pie_with_relro_and_bind_now_is_full(self) -> None:
        security = self._parse(_build_elf(
            e_type=3, gnu_stack_present=True, gnu_relro=True, bind_now=True,
            dynsym_names=(b"__stack_chk_fail", b"__printf_chk"),
        ))
        self.assertEqual(security["PIE"], "ON")
        self.assertEqual(security["NX"], "ON")
        self.assertEqual(security["RELRO"], "FULL")
        self.assertEqual(security["CANARY"], "ON")
        self.assertEqual(security["FORTIFY"], "ON")
        # 有节表但没有 .symtab → 已剥离（gcc -s 的形态）
        self.assertEqual(security["STRIPPED"], "ON")

    def test_relro_without_bind_now_is_partial(self) -> None:
        security = self._parse(_build_elf(e_type=3, gnu_relro=True, dynsym_names=(b"__stack_chk_fail",)))
        self.assertEqual(security["RELRO"], "PARTIAL")
        self.assertEqual(security["CANARY"], "ON")
        self.assertEqual(security["FORTIFY"], "OFF")

    def test_symtab_present_means_not_stripped(self) -> None:
        security = self._parse(_build_elf(with_symtab=True))
        self.assertEqual(security["STRIPPED"], "OFF")

    def test_garbage_file_stays_all_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "junk"
            path.write_bytes(b"not an elf at all")
            security = parse_elf_security(path)
        self.assertEqual(set(security.values()), {"UNKNOWN"})


if __name__ == "__main__":
    unittest.main()
