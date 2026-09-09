"""AWDP patch lab 真值单测：ELF 几何、code cave、seccomp 注入、recipes、导出。

全部使用手工构造的最小 ELF64 fixture（ET_EXEC、单 PT_LOAD R+X、
.text + 全零 cave + 节表），不依赖 WSL / 真实工具。
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch
import json
import struct
import subprocess
from zipfile import ZipFile

from pwncraft.core.wsl import ToolResult, WslToolRunner
from pwncraft.features.patch.patch_core import (
    PatchLab, PatchOp, entry_prefix_bytes, find_code_cave, parse_instruction_lines,
    rel32_jmp)
from pwncraft.features.patch.seccomp_inject import (
    SECCOMP_PRESETS, build_bpf_filter, build_install_shellcode, build_seccomp_ops,
    resolve_policy_names, shellcode_length)
from pwncraft.features.patch.recipes import (
    build_custom_bytes, build_jcc_invert, build_nop_function, build_nop_range,
    build_plt_call_redirect, build_plt_stub_redirect, build_read_length,
    build_ret_function, extract_plt_stubs, find_call_sites, normalize_patch_arch)
from pwncraft.features.patch.bytecode_catalog import (
    catalog_entries, disasm_raw, encode_template)
from pwncraft.features.patch.exporters import (
    export_competition_bundle, export_diff_text, export_pwntools_script, materialize_patched)
from pwncraft.features.patch.audit import audit_patch_surface

BASE = 0x400000
ENTRY_BYTES = b"\xf3\x0f\x1e\xfa\x31\xed\x5f\x5e"          # endbr64; xor ebp; pop rdi; pop rsi
STUB_READ = b"\xff\x25\x00\x00\x00\x00" + b"\x90" * 10      # 16 字节 PLT stub
STUB_EXIT = b"\xff\x25\x01\x00\x00\x00" + b"\x90" * 10
MAIN_CALL_REL = struct.pack("<i", (BASE + 0x80) - (BASE + 0xA0 + 15))
MAIN_BYTES = b"\xba\x2c\x01\x00\x00" + b"\xbf\x00\x00\x00\x00" + b"\xe8" + MAIN_CALL_REL


def insn_lines(start: int, chunks: list[tuple[bytes, str]]) -> str:
    lines, addr = [], start
    for blob, text in chunks:
        lines.append(f"  {addr:x}:\t{blob.hex(' ')}\t{text}")
        addr += len(blob)
    return "\n".join(lines)


ENTRY_ASSEMBLY = insn_lines(BASE + 0x78, [
    (b"\xf3\x0f\x1e\xfa", "endbr64"),
    (b"\x31\xed", "xor %ebp,%ebp"),
    (b"\x5f", "pop %rdi"),
    (b"\x5e", "pop %rsi"),
])
STUB_ASSEMBLY_READ = insn_lines(BASE + 0x80, [
    (b"\xff\x25\x00\x00\x00\x00", "jmpq *0x0(%rip)"),
    (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"),
    (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"),
    (b"\x90", "nop"), (b"\x90", "nop"),
])
STUB_ASSEMBLY_EXIT = insn_lines(BASE + 0x90, [
    (b"\xff\x25\x01\x00\x00\x00", "jmpq *0x1(%rip)"),
    (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"),
    (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"), (b"\x90", "nop"),
    (b"\x90", "nop"), (b"\x90", "nop"),
])
MAIN_ASSEMBLY = insn_lines(BASE + 0xA0, [
    (b"\xba\x2c\x01\x00\x00", "mov $0x12c,%edx"),
    (b"\xbf\x00\x00\x00\x00", "mov $0x0,%edi"),
    (b"\xe8" + MAIN_CALL_REL, "callq 400080 <read@plt>"),
])
TEXT_BLOB = ENTRY_BYTES + STUB_READ + STUB_EXIT + MAIN_BYTES   # 0x78..0xAF


def fake_functions() -> list[dict]:
    return [
        {"name": "read@plt", "address": "0x400080", "section": ".plt",
         "assembly": STUB_ASSEMBLY_READ},
        {"name": "exit@plt", "address": "0x400090", "section": ".plt",
         "assembly": STUB_ASSEMBLY_EXIT},
        {"name": ".plt", "address": "0x400060", "section": ".plt",
         "assembly": insn_lines(BASE + 0x60, [(b"\xff\x35\x02\x00\x00\x00", "push 0x2(%rip)")])},
        {"name": "system@plt", "address": "0x4000b0", "section": ".plt.sec",
         "assembly": insn_lines(BASE + 0xB0, [(b"\xf3\x0f\x1e\xfa", "endbr64"),
                                              (b"\xf2\xff\x25\x01\x00\x00\x00", "bnd jmp *0x1(%rip)"),
                                              (b"\x0f\x1f\x44\x00\x00", "nop 0x0(%rax,%rax,1)")])},
        {"name": "main", "address": "0x4000a0", "section": ".text",
         "assembly": MAIN_ASSEMBLY},
    ]


def fake_functions_legacy() -> list[dict]:
    """传统布局：无 .plt.sec，全部 @plt 在 .plt 节。"""
    return [fn for fn in fake_functions() if fn["section"] != ".plt.sec"]


def build_fixture(folder: Path, *, cave_size: int = 256) -> Path:
    """最小 ELF64：Ehdr + 1 个 R+X PT_LOAD + .text + 全零 cave + shstrtab + 节表。"""
    text_off = 0x78
    cave_off = text_off + len(TEXT_BLOB)
    shstr = b"\0.text\0.shstrtab\0"
    shstr_off = cave_off + cave_size
    shoff = (shstr_off + len(shstr) + 7) & ~7
    shnum = 3
    file_size = shoff + shnum * 64
    entry = BASE + text_off

    ehdr = bytearray(64)
    ehdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
                     2, 0x3E, 1, entry, 64, shoff, 0, 64, 56, 1, 64, shnum, 2)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, 0, file_size, file_size, 0x1000)
    sh_text = struct.pack("<IIQQQQIIQQ", 1, 1, 6, BASE + text_off, text_off,
                          len(TEXT_BLOB), 0, 0, 1, 0)
    sh_str = struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)

    data = bytearray(file_size)
    data[0:64] = ehdr
    data[64:120] = ph
    data[text_off:text_off + len(TEXT_BLOB)] = TEXT_BLOB
    data[shstr_off:shstr_off + len(shstr)] = shstr
    data[shoff + 64:shoff + 128] = sh_text
    data[shoff + 128:shoff + 192] = sh_str
    target = folder / "pwn"
    target.write_bytes(bytes(data))
    return target


class FixtureCase(TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.binary = build_fixture(self.folder)
        self.lab = PatchLab(self.binary)


class GeometryTests(FixtureCase):
    def test_geometry_maps_vaddr_to_offset(self):
        geo = self.lab.geometry()
        self.assertEqual(geo["entry"], BASE + 0x78)
        self.assertTrue(geo["is64"])
        self.assertEqual(self.lab.offset_of(BASE + 0x80), 0x80)
        with self.assertRaises(ValueError):
            self.lab.offset_of(0x100)

    def test_parse_instruction_lines(self):
        instructions = parse_instruction_lines(MAIN_ASSEMBLY)
        self.assertEqual([insn["address"] for insn in instructions],
                         [BASE + 0xA0, BASE + 0xA5, BASE + 0xAA])
        self.assertEqual(instructions[0]["bytes"], b"\xba\x2c\x01\x00\x00")
        self.assertEqual(instructions[0]["size"], 5)
        self.assertEqual(parse_instruction_lines("随便一行不是指令"), [])


class CodeCaveTests(FixtureCase):
    def test_page_aware_offset_falls_back_to_segment_tail(self):
        from pwncraft.features.patch.patch_core import page_aware_vaddr_to_offset
        # 模拟真实布局：RX 段 vaddr 0x401000 filesz 0x1d1，页尾填充到 0x402000
        geometry = {"file_size": 0x2338, "program_headers": [
            {"type": 1, "flags": 5, "offset": 0x1000, "vaddr": 0x401000,
             "filesz": 0x1d1, "memsz": 0x1d1, "align": 0x1000}], "sections": []}
        self.assertEqual(page_aware_vaddr_to_offset(geometry, 0x401100), 0x1100)
        self.assertEqual(page_aware_vaddr_to_offset(geometry, 0x4011d1), 0x11d1)
        self.assertEqual(page_aware_vaddr_to_offset(geometry, 0x402000), None)

    def test_cave_is_zero_padding_after_text(self):
        cave = find_code_cave(self.binary, 64)
        blob = self.lab.read(cave["offset"], cave["size"])
        self.assertTrue(set(blob) <= {0})
        self.assertEqual(cave["vaddr"], BASE + cave["offset"])
        # cave 不得覆盖 .text / 头部
        self.assertGreaterEqual(cave["offset"], 0x78 + len(TEXT_BLOB))

    def test_no_cave_raises_readable_error(self):
        import sys
        mod = sys.modules[__name__]
        original = mod.TEXT_BLOB
        try:
            mod.TEXT_BLOB = original + b"\x00" * 4
            with TemporaryDirectory() as folder:
                small = build_fixture(Path(folder))
                with self.assertRaises(ValueError):
                    find_code_cave(small, 512)
        finally:
            mod.TEXT_BLOB = original

    def test_cave_never_leaks_into_nonexec_segment_tail(self):
        # 双 LOAD 布局：RX 段尾只有 0x40 可用；R 段尾有 0x80 全零（旧版误选的陷阱）。
        # 修复前 R 段尾的零区被当成 cave，跳过去执行即 SIGSEGV（32 位实测踩坑）。
        text = TEXT_BLOB + b"\x00" * (0xFC0 - len(TEXT_BLOB))
        shoff = 0x21A0
        file_size = shoff + 4 * 64
        ehdr = bytearray(64)
        ehdr[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16,
                         2, 0x3E, 1, 0x401000, 64, shoff, 0, 64, 56, 2, 64, 4, 0)
        data = bytearray(file_size)
        data[0:64] = ehdr
        data[64:120] = struct.pack("<IIQQQQQQ", 1, 5, 0x1000, 0x401000, 0, 0xFC0, 0xFC0, 0x1000)
        data[120:176] = struct.pack("<IIQQQQQQ", 1, 4, 0x2000, 0x402000, 0, 0x100, 0x100, 0x1000)
        data[0x1000:0x1000 + len(text)] = text
        data[0x2000:0x2100] = b"\xcc" * 0x100          # .rodata（R 段内真实数据）
        data[0x2180:0x21A0] = b"\xee" * 0x20           # .dynamic 假数据
        data[shoff + 64:shoff + 128] = struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x401000, 0x1000, 0xFC0, 0, 0, 1, 0)
        data[shoff + 128:shoff + 192] = struct.pack("<IIQQQQIIQQ", 1, 1, 2, 0x402000, 0x2000, 0x100, 0, 0, 1, 0)
        data[shoff + 192:shoff + 256] = struct.pack("<IIQQQQIIQQ", 1, 6, 3, 0, 0x2180, 0x20, 0, 0, 1, 0)
        with TemporaryDirectory() as folder:
            split = Path(folder) / "split"
            split.write_bytes(bytes(data))
            with self.assertRaises(ValueError):
                find_code_cave(split, 0x60)
            cave = find_code_cave(split, 0x20)
            self.assertLess(cave["offset"], 0x2000)     # 必须落在可执行段范围内


class SeccompTests(FixtureCase):
    def test_bpf_filter_blacklist_and_whitelist(self):
        bpf = build_bpf_filter("amd64", kill=(59, 322))
        self.assertEqual(len(bpf), (5 + 2) * 8)
        insns = [struct.unpack("<HBBI", bpf[i:i + 8]) for i in range(0, len(bpf), 8)]
        self.assertEqual(insns[0], (0x20, 0, 0, 4))              # A = arch
        self.assertEqual(insns[1][0], 0x15)                        # JEQ arch
        self.assertEqual(insns[1][3], 0xC000003E)
        self.assertEqual(insns[1][2], 4)                           # jf → KILL 行
        self.assertEqual(insns[3][3], 59)
        self.assertEqual(insns[4][3], 322)
        self.assertEqual(insns[5], (0x06, 0, 0, 0x7FFF0000))       # 默认 ALLOW
        self.assertEqual(insns[6], (0x06, 0, 0, 0x80000000))       # 命中 KILL
        white = build_bpf_filter("amd64", allow=(0, 1))
        winsns = [struct.unpack("<HBBI", white[i:i + 8]) for i in range(0, len(white), 8)]
        self.assertEqual(winsns[5], (0x06, 0, 0, 0x80000000))      # 默认 KILL
        self.assertEqual(winsns[6], (0x06, 0, 0, 0x7FFF0000))      # 命中 ALLOW
        with self.assertRaises(ValueError):
            build_bpf_filter("arm", kill=(1,))
        with self.assertRaises(ValueError):
            build_bpf_filter("amd64")

    def test_shellcode_encoding_and_displacements(self):
        sc = build_install_shellcode("amd64", 0x1000, 0x1000 + 82, 7)
        self.assertEqual(len(sc), shellcode_length("amd64"))
        self.assertIn(b"\xb8\x9d\x00\x00\x00", sc)                  # mov eax,157
        self.assertIn(b"\xbf\x16\x00\x00\x00", sc)                  # mov edi,22
        self.assertEqual(sc[0], 0x52)                               # push rdx（保存 rtld_fini）
        self.assertEqual(sc[-1], 0x5A)                              # pop rdx
        self.assertEqual(sc[29:33], struct.pack("<i", 82 - 33))     # lea rip 位移
        sc32 = build_install_shellcode("i386", 0x2000, 0x2000 + 102, 9)
        self.assertEqual(len(sc32), shellcode_length("i386"))
        self.assertIn(b"\xb8\xac\x00\x00\x00", sc32)                # mov eax,172
        self.assertEqual(sc32[0], 0x52)                             # push edx（保存 rtld_fini）
        self.assertEqual(sc32[-1], 0x5A)                            # pop edx
        self.assertEqual(sc32[32:36], struct.pack("<i", 102 - 29))  # add ebx 位移（pop_at=29）

    def test_resolve_policy_names(self):
        self.assertEqual(resolve_policy_names(("execve", "execveat"), "amd64"), (59, 322))
        self.assertEqual(resolve_policy_names(["exit_group"], "i386"), (252,))
        with self.assertRaises(ValueError):
            resolve_policy_names(("not_a_syscall",), "amd64")

    def test_build_seccomp_ops_layout(self):
        entry_lines = parse_instruction_lines(ENTRY_ASSEMBLY)
        result = build_seccomp_ops(self.lab, arch="amd64",
                                   kill=("execve", "execveat"), entry_lines=entry_lines)
        ops = result["ops"]
        self.assertEqual(len(ops), 2)
        entry_op, cave_op = ops
        prefix_len = result["prefix_len"]
        self.assertEqual(prefix_len, 6)                             # endbr64 + xor ebp
        # 入口 → jmp cave + NOP 填充
        cave_vaddr = cave_op.vaddr
        self.assertEqual(entry_op.new_bytes[:5],
                         b"\xe9" + struct.pack("<i", cave_vaddr - (BASE + 0x78 + 5)))
        self.assertEqual(entry_op.new_bytes[5:], b"\x90")
        # cave 载荷 = shellcode + 原前缀 + 回跳 + BPF
        sc_len = shellcode_length("amd64")
        payload = cave_op.new_bytes
        self.assertEqual(len(payload), sc_len + 6 + 5 + (5 + 2) * 8)
        self.assertEqual(payload[sc_len:sc_len + 6], ENTRY_BYTES[:6])
        back_jmp_at = sc_len + 6
        self.assertEqual(payload[back_jmp_at:back_jmp_at + 5],
                         rel32_jmp(cave_vaddr + back_jmp_at, BASE + 0x78 + 6))
        self.assertEqual(payload[sc_len + 11:],
                         build_bpf_filter("amd64", kill=(59, 322)))

    def test_seccomp_roundtrip_apply_and_undo(self):
        entry_lines = parse_instruction_lines(ENTRY_ASSEMBLY)
        result = build_seccomp_ops(self.lab, arch="amd64",
                                   allow=("read", "write", "exit_group"),
                                   entry_lines=entry_lines)
        original = self.binary.read_bytes()
        applied = self.lab.apply(result["ops"])
        self.assertTrue(Path(applied["backup"]).is_file())
        self.assertNotEqual(self.binary.read_bytes(), original)
        restored = self.lab.undo_all()
        self.assertEqual(restored["count"], 2)
        self.assertEqual(self.binary.read_bytes(), original)

    def test_presets_are_self_consistent(self):
        for preset in SECCOMP_PRESETS.values():
            names = preset["kill"] if preset["default"] == "allow" else preset["allow"]
            self.assertTrue(names)
            self.assertTrue(resolve_policy_names(names, "amd64"))


class RecipeTests(FixtureCase):
    def test_plt_stubs_and_call_sites(self):
        # IBT 布局：@plt 入口在 .plt.sec，.plt 只剩名为 ".plt" 的整块（跳过）
        stubs = extract_plt_stubs(fake_functions())
        self.assertEqual(set(stubs), {"read", "exit", "system"})
        self.assertEqual(stubs["system"]["address"], BASE + 0xB0)
        self.assertEqual(stubs["system"]["size"], 16)
        # 传统布局：无 .plt.sec 时 @plt 直接在 .plt 节
        legacy = extract_plt_stubs(fake_functions_legacy())
        self.assertEqual(set(legacy), {"read", "exit"})
        self.assertEqual(legacy["read"]["address"], BASE + 0x80)
        self.assertEqual(legacy["read"]["size"], 16)
        sites = find_call_sites(fake_functions(), "read")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["insn"]["address"], BASE + 0xAA)

    def test_plt_call_redirect_recomputes_rel32(self):
        result = build_plt_call_redirect(self.lab, fake_functions(), "read", "exit")
        op = result["ops"][0]
        self.assertEqual(op.vaddr, BASE + 0xAA)
        expected = b"\xe8" + struct.pack("<i", (BASE + 0x90) - (BASE + 0xAA + 5))
        self.assertEqual(op.new_bytes, expected)
        with self.assertRaises(ValueError):
            build_plt_call_redirect(self.lab, fake_functions(), "nosuch", "exit")

    def test_plt_stub_redirect(self):
        op = build_plt_stub_redirect(self.lab, fake_functions(), "read", "exit")["ops"][0]
        self.assertEqual(op.new_bytes[:5],
                         b"\xe9" + struct.pack("<i", (BASE + 0x90) - (BASE + 0x80 + 5)))
        self.assertEqual(op.new_bytes[5:], b"\x90" * 11)

    def test_read_length_patch(self):
        op = build_read_length(self.lab, fake_functions(), "main", "read", 0x30)["ops"][0]
        self.assertEqual(op.vaddr, BASE + 0xA0)
        self.assertEqual(op.new_bytes, b"\xba\x30\x00\x00\x00")
        with self.assertRaises(ValueError):
            build_read_length(self.lab, fake_functions(), "main", "system", 0x30)

    def test_i386_read_length_patch_uses_third_stack_argument(self):
        assembly = insn_lines(0x8049000, [
            (b"\x68\x2c\x01\x00\x00", "push $0x12c"),
            (b"\x8d\x45\xb8", "lea -0x48(%ebp),%eax"),
            (b"\x50", "push %eax"),
            (b"\x6a\x00", "push $0x0"),
            (b"\xe8\x00\x00\x00\x00", "call 8048100 <read@plt>"),
        ])
        lab = Mock()
        lab.geometry.return_value = {"is64": False}
        lab.read_at.return_value = b"\x68\x2c\x01\x00\x00"
        lab.offset_of.side_effect = lambda address: address - 0x8048000
        functions = [{"name": "vuln", "assembly": assembly}]
        op = build_read_length(lab, functions, "vuln", "read", 0x40)["ops"][0]
        self.assertEqual(op.vaddr, 0x8049000)
        self.assertEqual(op.new_bytes, b"\x68\x40\x00\x00\x00")
        audit = audit_patch_surface(lab, functions)
        self.assertEqual(audit["findings"][0]["request"]["kind"], "readlen")

    def test_nop_and_ret_function(self):
        nop = build_nop_function(self.lab, fake_functions(), "main")["ops"][0]
        self.assertEqual(nop.new_bytes, b"\x90" * 15)
        self.assertEqual(nop.original_bytes, MAIN_BYTES)
        ret = build_ret_function(self.lab, fake_functions(), "main")["ops"][0]
        self.assertEqual(ret.new_bytes, b"\xc3")

    def test_nop_range_and_custom_bytes(self):
        op = build_nop_range(self.lab, BASE + 0xA0, BASE + 0xAA)["ops"][0]
        self.assertEqual(op.new_bytes, b"\x90" * 10)
        custom = build_custom_bytes(self.lab, BASE + 0xA0, "31 d2")["ops"][0]
        self.assertEqual(custom.new_bytes, b"\x31\xd2")
        with self.assertRaises(ValueError):
            build_custom_bytes(self.lab, BASE + 0xA0, "xyz")
        with self.assertRaises(ValueError):
            build_custom_bytes(self.lab, BASE + 0xA0, "ba")  # 与原首字节相同

    def test_jcc_invert(self):
        # 在 cave 空闲区手写跳转指令再反转（短跳转 jg → jle）
        with self.binary.open("r+b") as stream:
            stream.seek(0x200)
            stream.write(b"\x7f\x02\x90\x90")
        op = build_jcc_invert(self.lab, BASE + 0x200)["ops"][0]
        self.assertEqual(op.new_bytes, b"\x7e\x02")
        self.assertIn("jg", op.note)
        # 近跳转 0f 8f（jg rel32）→ 0f 8e（jle rel32），位移保留
        with self.binary.open("r+b") as stream:
            stream.seek(0x210)
            stream.write(b"\x0f\x8f\x10\x00\x00\x00")
        op2 = build_jcc_invert(self.lab, BASE + 0x210)["ops"][0]
        self.assertEqual(op2.new_bytes, b"\x0f\x8e\x10\x00\x00\x00")
        self.assertEqual(len(op2.original_bytes), 6)
        # 非跳转指令被拒绝
        with self.assertRaises(ValueError):
            build_jcc_invert(self.lab, BASE + 0x78)  # endbr64

    def test_normalize_patch_arch(self):
        self.assertEqual(normalize_patch_arch("x86-64", 64), "amd64")
        self.assertEqual(normalize_patch_arch("i386", 32), "i386")
        with self.assertRaises(ValueError):
            normalize_patch_arch("aarch64", 64)


class PatchLabTests(FixtureCase):
    def test_apply_undo_and_log(self):
        op = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                     original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5, note="t")
        self.lab.apply([op])
        self.assertEqual(self.lab.read(0xA0, 5), b"\x90" * 5)
        self.assertEqual(len(self.lab.log_ops()), 1)
        self.assertEqual(self.lab.log_ops()[0].note, "t")
        # 重叠补丁被拒绝
        clash = PatchOp(kind="custom", vaddr=BASE + 0xA2, file_offset=0xA2,
                        original_bytes=MAIN_BYTES[2:5], new_bytes=b"\x90" * 3)
        with self.assertRaises(ValueError):
            self.lab.apply([clash])
        self.lab.undo(self.lab.log_ops()[0].op_id)
        self.assertEqual(self.lab.read(0xA0, 5), MAIN_BYTES[:5])
        self.assertEqual(self.lab.log_ops(), [])

    def test_apply_rejects_stale_original_bytes(self):
        stale = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                        original_bytes=b"\xff" * 5, new_bytes=b"\x90" * 5)
        with self.assertRaises(ValueError):
            self.lab.apply([stale])

    def test_apply_rejects_overlap_inside_one_batch(self):
        first = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                        original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5)
        second = PatchOp(kind="custom", vaddr=BASE + 0xA4, file_offset=0xA4,
                         original_bytes=MAIN_BYTES[4:7], new_bytes=b"\xcc" * 3)
        before = self.binary.read_bytes()
        with self.assertRaisesRegex(ValueError, "重叠"):
            self.lab.apply([first, second])
        self.assertEqual(self.binary.read_bytes(), before)
        self.assertEqual(self.lab.log_ops(), [])

    def test_grouped_apply_is_undone_atomically(self):
        first = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                        original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5)
        second = PatchOp(kind="custom", vaddr=BASE + 0xA5, file_offset=0xA5,
                         original_bytes=MAIN_BYTES[5:10], new_bytes=b"\x31\xd2\x90\x90\x90")
        applied = self.lab.apply([first, second])
        logged = self.lab.log_ops()
        self.assertEqual({op.batch_id for op in logged}, {applied["batch_id"]})
        result = self.lab.undo(logged[0].op_id)
        self.assertEqual(result["count"], 2)
        self.assertEqual(self.binary.read_bytes(), build_fixture_bytes())
        self.assertEqual(self.lab.log_ops(), [])

    def test_reconcile_only_removes_fully_restored_groups(self):
        first = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                        original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5)
        second = PatchOp(kind="custom", vaddr=BASE + 0xA5, file_offset=0xA5,
                         original_bytes=MAIN_BYTES[5:10], new_bytes=b"\x31\xd2\x90\x90\x90")
        self.lab.apply([first, second])
        with self.binary.open("r+b") as stream:
            stream.seek(0xA0)
            stream.write(MAIN_BYTES[:5])
        partial = self.lab.reconcile_restored()
        self.assertEqual(partial, {"count": 0, "removed": [], "pending": 1})
        self.assertEqual(len(self.lab.log_ops()), 2)
        with self.binary.open("r+b") as stream:
            stream.seek(0xA5)
            stream.write(MAIN_BYTES[5:10])
        complete = self.lab.reconcile_restored()
        self.assertEqual(complete["count"], 2)
        self.assertEqual(complete["pending"], 0)
        self.assertEqual(self.lab.log_ops(), [])

    def test_integrity_states_and_reconcile_external_restore(self):
        op = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                     original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5)
        self.lab.apply([op])
        self.assertEqual(self.lab.inspect_ops()[0]["state"], "applied")
        with self.binary.open("r+b") as stream:
            stream.seek(0xA0)
            stream.write(MAIN_BYTES[:5])
        self.assertEqual(self.lab.inspect_ops()[0]["state"], "restored")
        self.assertEqual(self.lab.reconcile_restored()["count"], 1)
        self.assertEqual(self.lab.log_ops(), [])

    def test_conflict_blocks_single_and_full_undo_without_partial_write(self):
        first = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                        original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5)
        second = PatchOp(kind="custom", vaddr=BASE + 0xA5, file_offset=0xA5,
                         original_bytes=MAIN_BYTES[5:10], new_bytes=b"\x31\xd2\x90\x90\x90")
        self.lab.apply([first, second])
        with self.binary.open("r+b") as stream:
            stream.seek(0xA5)
            stream.write(b"\xcc" * 5)
        conflicted = self.binary.read_bytes()
        self.assertEqual(self.lab.integrity_summary()["conflict"], 1)
        with self.assertRaisesRegex(ValueError, "无法撤销补丁组"):
            self.lab.undo(self.lab.log_ops()[0].op_id)
        self.assertEqual(self.binary.read_bytes(), conflicted)
        with self.assertRaisesRegex(ValueError, "未修改任何字节"):
            self.lab.undo_all()
        self.assertEqual(self.binary.read_bytes(), conflicted)
        self.assertEqual(len(self.lab.log_ops()), 2)

    def test_log_write_failure_rolls_binary_back(self):
        op = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                     original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5)
        before = self.binary.read_bytes()
        self.lab._save_log = Mock(side_effect=OSError("disk full"))
        with self.assertRaisesRegex(OSError, "disk full"):
            self.lab.apply([op])
        self.assertEqual(self.binary.read_bytes(), before)

    def test_invalid_offset_and_corrupt_log_are_rejected(self):
        misplaced = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA1,
                            original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5)
        with self.assertRaisesRegex(ValueError, "应映射到"):
            self.lab.apply([misplaced])
        self.lab.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.lab.log_path.write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "补丁日志损坏"):
            self.lab.log_ops()

    def test_patchop_rejects_length_change(self):
        with self.assertRaises(ValueError):
            PatchOp(kind="custom", vaddr=0, file_offset=0,
                    original_bytes=b"\x90", new_bytes=b"\x90\x90")
        with self.assertRaisesRegex(ValueError, "不能为空"):
            PatchOp(kind="custom", vaddr=0, file_offset=0,
                    original_bytes=b"", new_bytes=b"")

    def test_entry_prefix_needs_five_bytes(self):
        lines = [{"address": BASE, "bytes": b"\x90", "size": 1, "text": "nop"}]
        with self.assertRaises(ValueError):
            entry_prefix_bytes(lines)
        self.assertEqual(entry_prefix_bytes(parse_instruction_lines(ENTRY_ASSEMBLY)),
                         b"\xf3\x0f\x1e\xfa\x31\xed")


class CatalogTests(TestCase):
    def test_catalog_lookup(self):
        nops = catalog_entries("nop")
        self.assertTrue(any(entry["mnemonic"] == "nop 5" for entry in nops))
        self.assertEqual(catalog_entries("e9 cd")[0]["mnemonic"], "jmp rel32")
        self.assertGreater(len(catalog_entries("")), 40)

    def test_assemble_keystone(self):
        from pwncraft.features.patch.bytecode_catalog import assemble
        try:
            import keystone  # noqa: F401
        except ImportError:
            self.skipTest("keystone-engine 未安装")
        result = assemble("mov edi, 0", bits=64, vaddr=0x401234)
        self.assertEqual(result["bytes"], "bf 00 00 00 00")
        self.assertEqual(result["size"], 5)
        jump = assemble("jmp 0x401234+0x100", bits=64, vaddr=0x401234)
        self.assertEqual(jump["bytes"], "e9 fb 00 00 00")   # rel32 = 0xfb
        x86 = assemble("push 0x30; mov ebx, 1", bits=32, vaddr=0x8048000)
        self.assertEqual(x86["bytes"], "6a 30 bb 01 00 00 00")
        with self.assertRaises(ValueError):
            assemble("", bits=64)
        with self.assertRaises(ValueError):
            assemble("??????", bits=64)

    def test_encode_templates(self):
        self.assertEqual(encode_template("nop", {"length": 5})["bytes"], "0f 1f 44 00 00")
        self.assertEqual(encode_template("mov_reg_imm32",
                                         {"register": "edx", "value": "0x30"})["bytes"],
                         "ba 30 00 00 00")
        self.assertEqual(encode_template("xor_reg", {"register": "edx"})["bytes"], "31 d2")
        self.assertEqual(encode_template("jmp_rel32", {"origin": "0x1000", "target": "0x2000"})["bytes"],
                         "e9 fb 0f 00 00")
        with self.assertRaises(ValueError):
            encode_template("keystone", {})

    def test_disasm_raw_parses_objdump(self):
        runner = Mock()
        runner.to_wsl_path.side_effect = lambda p: f"/mnt/x/{Path(p).name}"
        runner.run_tool.return_value = ToolResult(
            [], 0,
            "patch_disasm.bin:     file format binary\n\n"
            "Disassembly of section .data:\n\n"
            "0000000000000000 <.data>:\n"
            "   0:\t55              \tpush   rbp\n"
            "   1:\t48 89 e5        \tmov    rbp,rsp\n",
            "")
        with TemporaryDirectory() as folder:
            result = disasm_raw("55 48 89 e5", bits=64, runner=runner,
                                work_dir=Path(folder))
        self.assertEqual([insn["offset"] for insn in result["instructions"]], [0, 1])
        self.assertIn("push", result["instructions"][0]["text"])
        self.assertEqual(runner.run_tool.call_args.args[0], "objdump")
        self.assertIn("-b", runner.run_tool.call_args.args[1])


class ExporterTests(FixtureCase):
    def _two_ops(self):
        return [
            PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                    original_bytes=MAIN_BYTES[:5], new_bytes=b"\x90" * 5, note="NOP 测试"),
            PatchOp(kind="custom", vaddr=BASE + 0xA5, file_offset=0xA5,
                    original_bytes=MAIN_BYTES[5:10], new_bytes=b"\x31\xd2\x90\x90\x90",
                    note="xor edx"),
        ]

    def test_pwntools_script(self):
        script = export_pwntools_script(self._two_ops(), binary_name="pwn", arch="amd64")
        self.assertIn("context.arch = 'amd64'", script)
        self.assertIn("elf.write(0x4000a0, bytes.fromhex('90 90 90 90 90'))", script)
        self.assertIn("elf.save(output)", script)

    def test_pwntools_script_routes_tail_cave_to_offset_write(self):
        from pwncraft.core.workbench import vaddr_to_offset as strict
        geometry = {"program_headers": [
            {"type": 1, "flags": 5, "offset": 0, "vaddr": 0x400000,
             "filesz": 0x1000, "memsz": 0x1000, "align": 0x1000},
            {"type": 1, "flags": 5, "offset": 0x1000, "vaddr": 0x401000,
             "filesz": 0x1d1, "memsz": 0x1d1, "align": 0x1000}], "sections": []}
        body, tail = self._two_ops()
        self.assertIsNotNone(strict(geometry, body.vaddr))     # 普通 op 走 elf.write
        tail_cave = PatchOp(kind="seccomp_cave", vaddr=0x4011d1, file_offset=0x11d1,
                            original_bytes=b"\x00" * 4, new_bytes=b"\x90" * 4, note="cave")
        self.assertIsNone(strict(geometry, tail_cave.vaddr))   # 段尾 op 需要偏移补写
        script = export_pwntools_script([body, tail_cave], binary_name="pwn",
                                        arch="amd64", geometry=geometry)
        self.assertIn("elf.write(0x4000a0", script)
        self.assertIn("_tail_offset(elf, 0x4011d1)", script)
        self.assertIn("elf.save(output)", script)

    def test_diff_text(self):
        diff = export_diff_text(self._two_ops(), binary_path=str(self.binary))
        self.assertIn("vaddr 0x4000a0", diff)
        self.assertIn("ba 2c 01 00 00", diff)
        self.assertIn("NOP 测试", diff)

    def test_materialize_patched_replays_on_original(self):
        pristine = self.folder / "original"
        pristine.write_bytes(build_fixture_bytes())
        self.lab.apply(self._two_ops())
        dest = self.folder / "pwn_patched"
        result = materialize_patched(pristine, self.lab.log_ops(), dest)
        self.assertEqual(result["count"], 2)
        blob = dest.read_bytes()
        self.assertEqual(blob[0xA0:0xA5], b"\x90" * 5)
        self.assertEqual(blob[0xA5:0xAA], b"\x31\xd2\x90\x90\x90")
        # 原始副本与工作副本的其余字节保持一致
        self.assertEqual(blob[:0xA0], pristine.read_bytes()[:0xA0])

    def test_materialize_rejects_mismatched_source(self):
        pristine = self.folder / "original2"
        pristine.write_bytes(build_fixture_bytes())
        patched = PatchOp(kind="custom", vaddr=BASE + 0xA0, file_offset=0xA0,
                          original_bytes=b"\xff" * 5, new_bytes=b"\x90" * 5)
        with self.assertRaises(ValueError):
            materialize_patched(pristine, [patched], self.folder / "out")

    def test_competition_bundle_is_replayable_and_auditable(self):
        pristine = self.folder / "original"
        pristine.write_bytes(build_fixture_bytes())
        dest = self.folder / "submission.zip"
        result = export_competition_bundle(pristine, self._two_ops(), dest, arch="amd64")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["files"], ["original_patched", "patch.py", "patch.diff", "manifest.json"])
        with ZipFile(dest) as archive:
            self.assertEqual(set(archive.namelist()), set(result["files"]))
            manifest = json.loads(archive.read("manifest.json"))
            patched = archive.read("original_patched")
            self.assertEqual(manifest["operation_count"], 2)
            self.assertEqual(manifest["patched"]["size"], len(patched))
            self.assertEqual(patched[0xA0:0xA5], b"\x90" * 5)
            self.assertIn(b"elf.write(0x4000a0", archive.read("patch.py"))
            self.assertIn(b"vaddr 0x4000a0", archive.read("patch.diff"))


class AuditTests(FixtureCase):
    def test_scan_emits_previewable_read_and_command_mitigations(self):
        functions = fake_functions()
        functions.append({
            "name": "handler", "address": "0x4000c0", "section": ".text",
            "assembly": insn_lines(BASE + 0xC0, [
                (b"\xe8\x00\x00\x00\x00", "callq 4000b0 <system@plt>"),
            ]),
        })
        result = audit_patch_surface(self.lab, functions)
        by_id = {item["id"]: item for item in result["findings"]}
        self.assertEqual(by_id["length:read:main:4000a0"]["request"]["size"], "0x40")
        self.assertEqual(by_id["import:system"]["request"],
                         {"kind": "plt_call", "source": "system", "target": "exit"})
        self.assertEqual(by_id["mitigation:seccomp"]["request"]["kind"], "seccomp")
        self.assertGreaterEqual(result["summary"]["risk_score"], 30)

    def test_import_without_call_site_is_not_reported(self):
        result = audit_patch_surface(self.lab, fake_functions())
        ids = {item["id"] for item in result["findings"]}
        self.assertNotIn("import:system", ids)
        self.assertIn("length:read:main:4000a0", ids)


class WslStdinIsolationTests(TestCase):
    """WSL 查询工具不得继承桥的 stdin：wsl.exe 会把队列中的 JSON-RPC 请求行
    当输入吃掉，导致后续请求（如 patch 页并发发出的 patch_recipes）永久挂起。"""

    @patch("pwncraft.core.wsl.subprocess.run")
    def test_run_tool_passes_devnull_stdin(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
        WslToolRunner().run_tool("file", ["/bin/true"])
        self.assertEqual(run.call_args.kwargs.get("stdin"), subprocess.DEVNULL)

    @patch("pwncraft.core.pwndbg_manager.subprocess.run")
    def test_pwndbg_wsl_passes_devnull_stdin(self, run):
        from pwncraft.core.pwndbg_manager import PwndbgManager
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        PwndbgManager()._run_wsl("true")
        self.assertEqual(run.call_args.kwargs.get("stdin"), subprocess.DEVNULL)


class BridgePatchTests(FixtureCase):
    """rpc_patch_* 调度层：Mock objdump，验证 preview 不写盘、apply/undo/export 走通。"""

    FULL_DISASSEMBLY = (
        "Disassembly of section .plt:\n\n"
        "0000000000400080 <read@plt>:\n" + STUB_ASSEMBLY_READ + "\n"
        "0000000000400090 <exit@plt>:\n" + STUB_ASSEMBLY_EXIT + "\n"
        "Disassembly of section .text:\n\n"
        "00000000004000a0 <main>:\n" + MAIN_ASSEMBLY + "\n")

    def _bridge(self):
        from pwncraft.electron_bridge import ElectronBridge
        bridge = ElectronBridge()

        def run_tool(tool, args):
            if any(str(arg).startswith("--start-address") for arg in args):
                return ToolResult([], 0, ENTRY_ASSEMBLY, "")
            return ToolResult([], 0, self.FULL_DISASSEMBLY, "")

        runner = Mock()
        runner.to_wsl_path.side_effect = lambda p: f"/mnt/x/{Path(p).name}"
        runner.run_tool.side_effect = run_tool
        bridge._runner = runner
        return bridge

    def test_preview_does_not_touch_file(self):
        bridge = self._bridge()
        before = self.binary.read_bytes()
        result = bridge.rpc_patch_preview(
            {"path": str(self.binary), "request": {"kind": "nop_function", "function": "main"}})
        self.assertEqual(result["ops"][0]["new_bytes"].replace(" ", ""), "90" * 15)
        self.assertEqual(self.binary.read_bytes(), before)

    def test_apply_then_undo_via_rpc(self):
        bridge = self._bridge()
        params = {"path": str(self.binary),
                  "request": {"kind": "custom", "vaddr": hex(BASE + 0xA0), "hex": "31 d2 90 90 90"}}
        original = self.binary.read_bytes()
        applied = bridge.rpc_patch_apply(params)
        self.assertEqual(applied["backup"], applied["backup"])
        self.assertNotEqual(self.binary.read_bytes(), original)
        listed = bridge.rpc_patch_list({"path": str(self.binary)})
        self.assertEqual(len(listed["ops"]), 1)
        self.assertEqual(listed["ops"][0]["state"], "applied")
        self.assertTrue(listed["summary"]["healthy"])
        bridge.rpc_patch_undo({"path": str(self.binary), "op_id": listed["ops"][0]["op_id"]})
        self.assertEqual(self.binary.read_bytes(), original)

    def test_export_script_and_diff(self):
        bridge = self._bridge()
        bridge.rpc_patch_apply({"path": str(self.binary),
                                "request": {"kind": "ret_function", "function": "main"}})
        original = self.binary.read_bytes()
        script = bridge.rpc_patch_export({"path": str(self.binary), "kind": "script"})
        self.assertIn("elf.write(0x4000a0", script["text"])
        self.assertEqual(self.binary.read_bytes(), original,
                         "导出脚本不得写坏目标二进制（path/dest 歧义回归）")
        diff = bridge.rpc_patch_export({"path": str(self.binary), "kind": "diff"})
        self.assertIn("ret_function", diff["text"])
        written = bridge.rpc_patch_export({"path": str(self.binary), "kind": "diff",
                                           "dest": str(self.folder / "out.diff")})
        self.assertTrue((self.folder / "out.diff").is_file())
        self.assertIn("out.diff", written["path"])
        with self.assertRaises(ValueError):
            bridge.rpc_patch_export({"path": str(self.binary), "kind": "nope"})

    def test_audit_bundle_and_runtime_probe(self):
        bridge = self._bridge()
        pristine = self.folder / "original"
        pristine.write_bytes(build_fixture_bytes())
        bridge.workspace.target = {"working_binary": str(self.binary),
                                   "original_binary": str(pristine)}
        audit = bridge.rpc_patch_audit({"path": str(self.binary)})
        self.assertTrue(any(item["id"].startswith("length:read") for item in audit["findings"]))
        bridge.rpc_patch_apply({"path": str(self.binary), "request": {
            "kind": "custom", "vaddr": hex(BASE + 0xA0), "hex": "31 d2 90 90 90"}})
        bundle = bridge.rpc_patch_export({"path": str(self.binary), "kind": "bundle",
                                          "dest": str(self.folder / "submission.zip")})
        self.assertEqual(bundle["count"], 1)
        self.assertTrue(Path(bundle["path"]).is_file())
        bridge._runner.run_target_capture.return_value = (
            ToolResult(["pwn"], 0, "READY\n", ""), False)
        probe = bridge.rpc_patch_probe({"path": str(self.binary), "args": "--mode test",
                                        "input": "ping\n", "timeout": 3, "compare": True})
        self.assertTrue(probe["patched"]["ok"])
        self.assertTrue(probe["comparison"]["same_stdout"])
        self.assertEqual(probe["args"], ["--mode", "test"])
        self.assertEqual(bridge._runner.run_target_capture.call_count, 2)
        first = bridge._runner.run_target_capture.call_args_list[0]
        self.assertEqual(first.kwargs["stdin_data"], b"ping\n")
        self.assertEqual(first.kwargs["timeout"], 3)
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            bridge.rpc_patch_probe({"path": str(self.binary), "input": "x" * 65537})

    def test_seccomp_rpc_end_to_end(self):
        bridge = self._bridge()
        original = self.binary.read_bytes()
        result = bridge.rpc_patch_apply(
            {"path": str(self.binary),
             "request": {"kind": "seccomp", "preset": "blacklist_min"}})
        self.assertEqual(len(result["applied"]), 2)
        self.assertNotEqual(self.binary.read_bytes(), original)
        listed = bridge.rpc_patch_list({"path": str(self.binary)})
        undone = bridge.rpc_patch_undo(
            {"path": str(self.binary), "op_id": listed["ops"][0]["op_id"]})
        self.assertEqual(undone["count"], 2)
        self.assertEqual(self.binary.read_bytes(), original)

    def test_rpc_blocks_export_until_external_restore_is_reconciled(self):
        bridge = self._bridge()
        bridge.rpc_patch_apply(
            {"path": str(self.binary),
             "request": {"kind": "custom", "vaddr": hex(BASE + 0xA0),
                         "hex": "31 d2 90 90 90"}})
        with self.binary.open("r+b") as stream:
            stream.seek(0xA0)
            stream.write(MAIN_BYTES[:5])
        listed = bridge.rpc_patch_list({"path": str(self.binary)})
        self.assertEqual(listed["summary"]["restored"], 1)
        with self.assertRaisesRegex(ValueError, "补丁记录与工作副本不一致"):
            bridge.rpc_patch_export({"path": str(self.binary), "kind": "script"})
        reconciled = bridge.rpc_patch_reconcile({"path": str(self.binary)})
        self.assertEqual(reconciled["count"], 1)
        self.assertEqual(reconciled["log"], [])

    def test_bytecode_rpc_surface(self):
        bridge = self._bridge()
        entries = bridge.rpc_patch_bytecode_lookup({"query": "nop"})["entries"]
        self.assertTrue(entries)
        encoded = bridge.rpc_patch_encode(
            {"kind": "mov_reg_imm32", "params": {"register": "edx", "value": "0x30"}})
        self.assertEqual(encoded["bytes"], "ba 30 00 00 00")
        instructions = bridge.rpc_patch_instructions(
            {"path": str(self.binary), "function": "main"})["instructions"]
        self.assertEqual(instructions[0]["bytes"], "ba 2c 01 00 00")

    def test_unknown_request_kind_is_rejected(self):
        bridge = self._bridge()
        with self.assertRaises(ValueError):
            bridge.rpc_patch_preview({"path": str(self.binary), "request": {"kind": "magic"}})


def build_fixture_bytes() -> bytes:
    """与 build_fixture 相同布局的字节串（不落盘）。"""
    with TemporaryDirectory() as folder:
        return build_fixture(Path(folder)).read_bytes()
