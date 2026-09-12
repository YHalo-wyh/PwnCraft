"""漏洞点确认单测：长度 vs 缓冲区边界的判定 golden（纯 AT&T 文本 fixture，无 WSL）。"""
from unittest import TestCase
from unittest.mock import patch

from pwncraft.features.synth.vuln_points import _parse_object_symbols, canonical_callee, scan_functions


def test_custom_allocator_aliases_reuse_existing_lifetime_semantics():
    assert canonical_callee("pMalloc@@Base") == "malloc"
    assert canonical_callee("pFree@plt") == "free"
    assert canonical_callee("pFree@plt+0x25e") == "pFree"
from pwncraft.features.synth import vuln_points


def _lines(*pairs) -> str:
    return "\n".join(f"  {addr:x}:\t00 00       \t{text}" for addr, text in pairs)


VULN_MAIN = _lines(
    (0x4011b5, "push %rbp"),
    (0x4011b6, "mov %rsp,%rbp"),
    (0x4011b9, "sub $0x30,%rsp"),
    (0x4011bd, "mov %fs:0x28,%rax"),
    (0x4011c6, "mov %rax,-0x8(%rbp)"),
    (0x4011ca, "lea -0x30(%rbp),%rax"),
    (0x4011ce, "mov $0x200,%edx"),
    (0x4011d3, "mov %rax,%rsi"),
    (0x4011d6, "mov $0x0,%edi"),
    (0x4011db, "callq 401030 <read@plt>"),
    (0x4011e0, "lea -0x60(%rbp),%rax"),
    (0x4011e4, "mov $0x18,%edx"),
    (0x4011e9, "mov %rax,%rsi"),
    (0x4011ec, "mov $0x0,%edi"),
    (0x4011f0, "callq 401030 <read@plt>"),
)

MMAP_MAIN = _lines(
    (0x4011e0, "mov $0x1338000,%edi"),
    (0x4011e5, "mov $0x1000,%esi"),
    (0x4011ea, "mov $0x7,%edx"),
    (0x4011ef, "callq 401020 <mmap@plt>"),
    (0x4011f4, "mov %rax,%rbx"),
    (0x4011f7, "mov $0x1000,%edx"),
    (0x4011fc, "mov %rbx,%rsi"),
    (0x4011ff, "xor %edi,%edi"),
    (0x401201, "callq 401040 <read@plt>"),
)

GETS_MAIN = _lines(
    (0x401210, "lea -0x30(%rbp),%rax"),
    (0x401214, "mov %rax,%rdi"),
    (0x401217, "callq 401050 <gets@plt>"),
)

MALLOC_OVERFLOW = _lines(
    (0x401220, "mov $0x20,%edi"),
    (0x401225, "callq 401060 <malloc@plt>"),
    (0x40122a, "mov %rax,%rbx"),
    (0x40122d, "mov $0x100,%edx"),
    (0x401232, "mov %rbx,%rsi"),
    (0x401235, "xor %edi,%edi"),
    (0x401238, "callq 401030 <read@plt>"),
)

NONCONST_MAIN = _lines(
    (0x401240, "lea -0x40(%rbp),%rax"),
    (0x401244, "mov -0x54(%rbp),%edx"),
    (0x401247, "mov %rax,%rsi"),
    (0x40124a, "mov $0x0,%edi"),
    (0x40124e, "callq 401030 <read@plt>"),
)

RECV_MAIN = _lines(
    (0x401260, "lea -0x40(%rbp),%rax"),
    (0x401264, "mov $0x100,%edx"),
    (0x401269, "mov %rax,%rsi"),
    (0x40126c, "mov $0x4,%edi"),
    (0x401271, "callq 401070 <recv@plt>"),
)

MEMCPY_MAIN = _lines(
    (0x401280, "lea -0x20(%rbp),%rax"),
    (0x401284, "mov $0x80,%edx"),
    (0x401289, "mov %rbx,%rsi"),
    (0x40128c, "mov %rax,%rdi"),
    (0x40128f, "callq 401080 <memcpy@plt>"),
)

I386_READ = _lines(
    (0x8049100, "lea -0x20(%ebp),%eax"),
    (0x8049104, "push $0x80"),
    (0x8049109, "push %eax"),
    (0x804910a, "push $0x0"),
    (0x804910c, "call 8048300 <read@plt>"),
)

STRCPY_STACK = _lines(
    (0x401500, "lea -0x30(%rbp),%rdi"),
    (0x401504, "call 401030 <strcpy@plt>"),
)

ARITHMETIC_LENGTH = _lines(
    (0x401510, "lea -0x20(%rbp),%rsi"),
    (0x401514, "mov $0x20,%edx"),
    (0x401519, "shl $0x2,%edx"),
    (0x40151c, "xor %edi,%edi"),
    (0x40151e, "call 401030 <read@plt>"),
)

CALLOC_OVERFLOW = _lines(
    (0x401520, "mov $0x8,%edi"),
    (0x401525, "mov $0x4,%esi"),
    (0x40152a, "call 401090 <calloc@plt>"),
    (0x40152f, "mov %rax,%rbx"),
    (0x401532, "mov $0x30,%edx"),
    (0x401537, "mov %rbx,%rsi"),
    (0x40153a, "xor %edi,%edi"),
    (0x40153c, "call 401030 <read@plt>"),
)

GLOBAL_OVERFLOW = _lines(
    (0x401540, "lea 0x2ef9(%rip),%rsi # 404040 <input_buf>"),
    (0x401547, "mov $0x80,%edx"),
    (0x40154c, "xor %edi,%edi"),
    (0x40154e, "call 401030 <read@plt>"),
)

FORMAT_AND_COMMAND = _lines(
    (0x401560, "mov -0x18(%rbp),%rdi"),
    (0x401564, "call 4010a0 <printf@plt>"),
    (0x401569, "mov -0x20(%rbp),%rdi"),
    (0x40156d, "call 4010b0 <system@plt>"),
)

HEAP_LIFETIME = _lines(
    (0x401580, "mov %rax,-0x8(%rbp)"),
    (0x401584, "mov -0x8(%rbp),%rdi"),
    (0x401588, "call 4010c0 <free@plt>"),
    (0x40158d, "mov -0x8(%rbp),%rdi"),
    (0x401591, "call 4010d0 <puts@plt>"),
    (0x401596, "mov -0x8(%rbp),%rdi"),
    (0x40159a, "call 4010c0 <free@plt>"),
)

STACK_RETURN = _lines(
    (0x4015a0, "lea -0x20(%rbp),%rax"),
    (0x4015a4, "ret"),
)

WRAPPER = _lines(
    (0x401600, "mov %rsi,%rdx"),
    (0x401603, "mov %rdi,%rsi"),
    (0x401606, "xor %edi,%edi"),
    (0x401608, "call 401030 <read@plt>"),
)

WRAPPER_CALLER = _lines(
    (0x401620, "lea -0x20(%rbp),%rdi"),
    (0x401624, "mov $0x100,%esi"),
    (0x401629, "call 401600 <read_wrapper>"),
)

FREAD_PRODUCT = _lines(
    (0x401640, "lea -0x20(%rbp),%rdi"),
    (0x401644, "mov $0x10,%esi"),
    (0x401649, "mov $0x8,%edx"),
    (0x40164e, "mov %rbx,%rcx"),
    (0x401651, "call 401100 <fread@plt>"),
)


def _one(assembly):
    return scan_functions([{"name": "main", "assembly": assembly}])[0]


class VulnPointsTests(TestCase):
    def test_confirmed_overflow_is_canary_aware(self):
        points = scan_functions([{"name": "main", "assembly": VULN_MAIN}])
        self.assertEqual(len(points), 2)
        bad, safe = points
        self.assertEqual(bad["verdict"], "overflow_confirmed")
        self.assertEqual(bad["length"], 0x200)
        self.assertEqual(bad["bound"], 0x38)          # rbp-0x30 → 距保存 RIP 0x38
        self.assertIn("覆盖返回地址", bad["reason"])
        self.assertEqual(safe["verdict"], "within_bound")
        self.assertEqual(safe["bound"], 0x58)         # 0x60 - canary 槽 0x8

    def test_mmap_same_size_is_within_bound(self):
        point = _one(MMAP_MAIN)
        self.assertEqual(point["verdict"], "within_bound")
        self.assertEqual(point["length"], 0x1000)
        self.assertEqual(point["bound"], 0x1000)
        self.assertIn("mmap", point["reason"])

    def test_mmap_prot_assignment_does_not_poison_length(self):
        # edx=7 是 mmap 的 prot；最近赋值获胜后应为 0x1000 而非 0x7
        point = _one(MMAP_MAIN)
        self.assertEqual(point["length"], 0x1000)

    def test_gets_is_unbounded_confirmed(self):
        point = _one(GETS_MAIN)
        self.assertEqual(point["verdict"], "overflow_confirmed")
        self.assertEqual(point["callee"], "gets")

    def test_malloc_overflow_confirmed(self):
        point = _one(MALLOC_OVERFLOW)
        self.assertEqual(point["verdict"], "overflow_confirmed")
        self.assertEqual(point["buffer"], {"kind": "alloc", "size": 0x20})
        self.assertEqual(point["bound"], 0x20)

    def test_nonconstant_length_is_honest_unknown(self):
        point = _one(NONCONST_MAIN)
        self.assertEqual(point["verdict"], "unknown_length")
        self.assertIsNone(point["length"])

    def test_recv_uses_buffer_and_third_argument_like_read(self):
        point = _one(RECV_MAIN)
        self.assertEqual(point["callee"], "recv")
        self.assertEqual(point["verdict"], "overflow_confirmed")
        self.assertEqual(point["length"], 0x100)

    def test_memcpy_length_is_compared_with_destination_stack_slot(self):
        point = _one(MEMCPY_MAIN)
        self.assertEqual(point["callee"], "memcpy")
        self.assertEqual(point["verdict"], "overflow_confirmed")
        self.assertEqual(point["length"], 0x80)

    def test_unbounded_copy_is_flagged_without_claiming_source_length(self):
        point = _one(STRCPY_STACK)
        self.assertEqual(point["callee"], "strcpy")
        self.assertEqual(point["verdict"], "unbounded_input")
        self.assertIn("源长度未解析", point["reason"])

    def test_i386_cdecl_read_arguments_are_proven(self):
        point = scan_functions([{"name": "handler", "assembly": I386_READ}], bits=32)[0]
        self.assertEqual(point["verdict"], "overflow_confirmed")
        self.assertEqual(point["length"], 0x80)
        self.assertEqual(point["bound"], 0x24)

    def test_simple_constant_arithmetic_is_propagated(self):
        point = _one(ARITHMETIC_LENGTH)
        self.assertEqual(point["length"], 0x80)
        self.assertEqual(point["verdict"], "overflow_confirmed")
        self.assertEqual(point["request"]["vaddr"], "0x401514")

    def test_calloc_product_is_used_as_heap_capacity(self):
        point = _one(CALLOC_OVERFLOW)
        self.assertEqual(point["buffer"], {"kind": "alloc", "size": 0x20})
        self.assertEqual(point["verdict"], "overflow_confirmed")

    def test_global_symbol_size_proves_overflow(self):
        point = scan_functions(
            [{"name": "main", "assembly": GLOBAL_OVERFLOW}],
            objects=[{"name": "input_buf", "address": 0x404040, "size": 0x40}])[0]
        self.assertEqual(point["buffer"]["symbol"], "input_buf")
        self.assertEqual(point["bound"], 0x40)
        self.assertEqual(point["verdict"], "overflow_confirmed")

    def test_nonliteral_format_and_command_arguments_are_candidates(self):
        points = scan_functions([{"name": "main", "assembly": FORMAT_AND_COMMAND}])
        verdicts = {point["callee"]: point["verdict"] for point in points}
        self.assertEqual(verdicts["printf"], "format_string_candidate")
        self.assertEqual(verdicts["system"], "command_injection_candidate")

    def test_double_free_and_call_use_after_free(self):
        points = scan_functions([{"name": "handler", "assembly": HEAP_LIFETIME}])
        verdicts = {point["verdict"] for point in points}
        self.assertIn("double_free_candidate", verdicts)
        self.assertIn("use_after_free_candidate", verdicts)

    def test_stack_address_return_is_reported(self):
        point = _one(STACK_RETURN)
        self.assertEqual(point["verdict"], "stack_address_return")

    def test_one_level_wrapper_propagates_buffer_and_length(self):
        points = scan_functions([
            {"name": "read_wrapper", "assembly": WRAPPER},
            {"name": "main", "assembly": WRAPPER_CALLER},
        ])
        derived = next(point for point in points if point.get("via") == "read_wrapper")
        self.assertEqual(derived["callee"], "read")
        self.assertEqual(derived["length"], 0x100)
        self.assertEqual(derived["verdict"], "overflow_confirmed")

    def test_fread_multiplies_element_size_and_count(self):
        point = _one(FREAD_PRODUCT)
        self.assertEqual(point["length"], 0x80)
        self.assertEqual(point["verdict"], "overflow_confirmed")

    def test_readelf_object_symbols_are_deduplicated(self):
        output = """
          12: 0000000000404040    64 OBJECT  GLOBAL DEFAULT   25 input_buf
          29: 0000000000404040    64 OBJECT  GLOBAL DEFAULT   25 input_buf
          30: 0000000000000000     0 OBJECT  GLOBAL DEFAULT  UND stdin
        """
        self.assertEqual(_parse_object_symbols(output), [
            {"address": 0x404040, "size": 64, "name": "input_buf"}])

    def test_resolved_scanf_format_does_not_raise_and_flags_unbounded_s(self):
        with patch.object(vuln_points, "_resolve_fmt_string",
                          return_value={"resolved": True, "fmt": "%s"}):
            result = vuln_points._scanf_dangerous([], 0, None)
        self.assertTrue(result["danger"])

    def test_sorting_puts_confirmed_first(self):
        points = scan_functions([{"name": "main", "assembly": VULN_MAIN}])
        self.assertEqual(points[0]["verdict"], "overflow_confirmed")

    def test_empty_input(self):
        self.assertEqual(scan_functions([]), [])
        self.assertEqual(scan_functions([{"name": "f", "assembly": ""}]), [])


# --- v4：函数边界恢复 / 可写段数据流 / i386 PIC / 指针步进写 ---------------

FRAMES_OUTPUT = _lines(
    (0x18, "00000014 0000001c FDE cie=00000000 pc=00000000000012a0..00000000000012c6"),
    (0x30, "0000001c 00000034 FDE cie=00000000 pc=0000000000001389..00000000000013ce"),
    (0x50, "00000014 00000054 CIE"),
    (0x70, "0000001c 00000074 FDE cie=00000000 pc=0000000000001cd5..0000000000001d30"),
)

BLOB_DISASSEMBLY = _lines(
    (0x12a0, "push %rbp"),
    (0x12a4, "mov %rsp,%rbp"),
    (0x1389, "push %rbp"),
    (0x138d, "mov %rsp,%rbp"),
    (0x1cd5, "push %rbp"),
)


class FunctionRecoveryTests(TestCase):
    def test_fde_ranges_take_readelf_pc_pairs(self):
        self.assertEqual(
            vuln_points.parse_fde_ranges(FRAMES_OUTPUT),
            [(0x12A0, 0x12C6), (0x1389, 0x13CE), (0x1CD5, 0x1D30)])

    def test_fde_ranges_on_empty_output(self):
        self.assertEqual(vuln_points.parse_fde_ranges(""), [])

    def test_blob_is_split_at_fde_boundaries(self):
        text_section = {"addr": 0x12A0, "size": 0xB00}
        functions = vuln_points.recover_functions(BLOB_DISASSEMBLY, FRAMES_OUTPUT,
                                                  text_section)
        self.assertEqual([fn["name"] for fn in functions],
                         ["sub_12a0", "sub_1389", "sub_1cd5"])
        self.assertEqual([fn["instruction_count"] for fn in functions], [2, 2, 1])
        self.assertTrue(all(fn["recovered"] == "eh_frame" for fn in functions))

    def test_no_fde_means_no_recovery(self):
        self.assertEqual(
            vuln_points.recover_functions(BLOB_DISASSEMBLY, "", {"addr": 0x12A0, "size": 0xB00}),
            [])

    def test_fde_outside_text_section_is_ignored(self):
        frames = "0000001c 00000074 FDE cie=00000000 pc=0000000000009999..000000000000999f"
        self.assertEqual(
            vuln_points.recover_functions(BLOB_DISASSEMBLY, frames,
                                          {"addr": 0x12A0, "size": 0xB00}),
            [])


class I386PicTests(TestCase):
    I386_PIC = _lines(
        (0xE64, "call 750 <__x86.get_pc_thunk.bx>"),
        (0xE69, "add $0x213b,%ebx"),
        (0xE72, "lea -0x1d00(%ebx),%eax"),
        (0xE78, "push %eax"),
        (0xE79, "call 5e0 <system@plt>"),
    )

    def test_get_pc_thunk_plus_add_yields_got_base(self):
        lines = vuln_points.parse_instruction_lines(self.I386_PIC)
        self.assertEqual(vuln_points._i386_got_base(lines), 0xE69 + 0x213B)

    def test_ebx_relative_lea_resolves_to_absolute_global(self):
        lines = vuln_points.parse_instruction_lines(self.I386_PIC)
        base = vuln_points._i386_got_base(lines)
        chain = vuln_points._backtrack(lines, 4, "eax", got_base=base)
        self.assertEqual(chain["kind"], "rip")
        # 0xe69 + 0x213b - 0x1d00 —— 即 p2048 win() 里固定的 "/bin/sh"(.rodata)
        self.assertEqual(chain["address"], 0xE69 + 0x213B - 0x1D00)
        self.assertEqual(chain["pic"], "ebx")

    def test_fortify_format_argument_index_is_shifted(self):
        self.assertEqual(vuln_points._fmt_arg_index("__printf_chk", 64), 1)
        self.assertEqual(vuln_points._fmt_arg_index("__printf_chk", 32), 1)
        self.assertEqual(vuln_points._fmt_arg_index("__fprintf_chk", 64), 2)
        self.assertEqual(vuln_points._fmt_arg_index("__snprintf_chk", 64), 4)
        self.assertEqual(vuln_points._fmt_arg_index("printf", 64), 0)


class PointerStepWriteTests(TestCase):
    # 真实形态（2023 春秋杯 p2048 game 主循环）：inc 之后才写，再回跳。
    UNBOUNDED = _lines(
        (0x10D8, "mov -0x41d(%ebp),%al"),
        (0x10DE, "inc %edi"),
        (0x10E1, "mov %al,-0x1(%edi)"),
        (0x10E3, "jmp 10d0 <game+0x1ba>"),
    )
    GUARDED = _lines(
        (0x2000, "cmp %esi,%edi"),
        (0x2002, "jae 2040 <loop+0x40>"),
        (0x2004, "mov %al,-0x1(%edi)"),
        (0x2006, "inc %edi"),
        (0x2008, "jmp 2000 <loop+0x0>"),
    )

    def test_unbounded_pointer_step_write_is_reported(self):
        points = vuln_points._pointer_step_points(
            {"name": "game"}, vuln_points.parse_instruction_lines(self.UNBOUNDED), 32)
        self.assertEqual([p["verdict"] for p in points], ["pointer_step_overflow"])
        self.assertEqual(points[0]["severity"], "critical")
        self.assertEqual(points[0]["confidence"], "dataflow")

    # 真实形态（2023 春秋杯 p2048 game 主循环）：循环体里塞满了与指针无关的
    # cmpb（按键分发），但它们不构成 edi 的上界 → 仍须报出漏洞。
    UNRELATED_CMP = _lines(
        (0x10DC, "mov -0x41d(%ebp),%al"),
        (0x10E2, "inc %edi"),
        (0x10E3, "mov %al,-0x1(%edi)"),
        (0x10E6, "jmp f51 <game+0x3b>"),
    )

    def test_unrelated_cmp_in_loop_does_not_mask_the_bug(self):
        lines = vuln_points.parse_instruction_lines(self.UNRELATED_CMP + _lines(
            (0x1050, "cmpb $0x72,-0x41d(%ebp)"),
            (0x1057, "jne 108b <game+0x175>"),
            (0x108B, "cmpb $0x72,-0x41d(%ebp)"),
            (0x1092, "jne 10dc <game+0x1c6>"),
        ))
        lines.sort(key=lambda item: item["address"])
        points = vuln_points._pointer_step_points({"name": "game"}, lines, 32)
        self.assertEqual([p["verdict"] for p in points], ["pointer_step_overflow"])
        self.assertEqual(points[0]["vaddr"], "0x10e3")

    def test_mentions_register_normalises_width_aliases(self):
        self.assertTrue(vuln_points._mentions_register("cmp %esi,%edi", "edi"))
        self.assertTrue(vuln_points._mentions_register("cmp $0x10,%rdi", "edi"))
        self.assertFalse(vuln_points._mentions_register("cmpb $0x72,-0x41d(%ebp)", "edi"))
        self.assertFalse(vuln_points._mentions_register("cmp $0x79,%al", "edi"))

    def test_bounded_loop_is_not_reported(self):
        self.assertEqual(
            vuln_points._pointer_step_points(
                {"name": "loop"}, vuln_points.parse_instruction_lines(self.GUARDED), 32),
            [])


class WrittenGlobalsTests(TestCase):
    def test_dest_of_bounded_read_into_global_is_recorded(self):
        # lea 0x3256(%rip),%rax -> 全局 0x4968；随后 fgets 用它做 dest
        assembly = _lines(
            (0x170B, "lea 0x3256(%rip),%rax        # 4968"),
            (0x1712, "mov %rax,%rdi"),
            (0x1715, "call 1230 <fgets@plt>"),
        )
        lines = vuln_points.parse_instruction_lines(assembly)
        # _backtrack 取注释里的地址，_written_globals 记录该全局被写
        self.assertIn(0x4968, vuln_points._written_globals(lines, 64))

    def test_direct_rip_store_is_recorded(self):
        assembly = _lines((0x15A3, "movl $0x1,0x33b3(%rip)        # 4960"),)
        lines = vuln_points.parse_instruction_lines(assembly)
        self.assertIn(0x4960, vuln_points._written_globals(lines, 64))


class OffByOneTests(TestCase):
    # 真实形态（2023 春秋杯 babyaul add_chunk 0x6261）：
    #   read(0, ptrs[i], size) → mov -0xc(%rbp),%eax(size) → add %rdx,%rax → movb $0x0,(%rax)
    # 中间夹着编译器生成的 `push %r8; addq $0x8,(%rsp); ret` 跳板，不得因此中断。
    OFF_BY_ONE = _lines(
        (0x64B6, "mov -0xc(%rbp),%edx"),
        (0x64D4, "mov $0x0,%edi"),
        (0x64D9, "call 58a0 <read@plt>"),
        (0x64DE, "lea 0x0(%rip),%r8"),
        (0x64E5, "push %r8"),
        (0x64E7, "addq $0x8,(%rsp)"),
        (0x64EC, "ret"),
        (0x6501, "mov (%rdx,%rax,1),%rax"),
        (0x6522, "mov -0xc(%rbp),%eax"),
        (0x6525, "add %rdx,%rax"),
        (0x6528, "movb $0x0,(%rax)"),
    )

    def test_terminator_write_past_read_length_is_reported(self):
        points = vuln_points._off_by_one_points(
            {"name": "add_chunk"}, vuln_points.parse_instruction_lines(self.OFF_BY_ONE),
            64, None, None)
        self.assertEqual([p["verdict"] for p in points], ["off_by_one_null_write"])
        self.assertEqual(points[0]["vaddr"], "0x6528")
        self.assertEqual(points[0]["severity"], "critical")

    def test_unrelated_store_is_not_reported(self):
        # 写入下标与读入长度不同源（长度来自 -0xc，下标来自 -0x30）→ 不报
        assembly = _lines(
            (0x1000, "mov -0xc(%rbp),%edx"),
            (0x1003, "mov $0x0,%edi"),
            (0x1006, "call 900 <read@plt>"),
            (0x100B, "mov -0x30(%rbp),%eax"),
            (0x100E, "add %rdx,%rax"),
            (0x1011, "movb $0x0,(%rax)"),
        )
        self.assertEqual(
            vuln_points._off_by_one_points(
                {"name": "f"}, vuln_points.parse_instruction_lines(assembly),
                64, None, None),
            [])


class UsableSizeTests(TestCase):
    """glibc 可用区公式：只有 size%16==8 时 usable == size，`buf[size]=0` 才越界。"""

    def test_usable_size_matches_glibc_rounding(self):
        for size in (0x18, 0xF8, 0x4F8, 0x508, 0x518):
            self.assertEqual(vuln_points._usable_size(size), size, hex(size))
        for size in (0x100, 0x110, 0x20, 0x4F0):
            self.assertGreater(vuln_points._usable_size(size), size, hex(size))

    def test_off_by_one_uses_malloc_size_when_constant(self):
        # malloc(0x100) → usable 0x108 > 0x100 → 终止符仍在可用区内 → 不报
        assembly = _lines(
            (0x1000, "mov $0x100,%edi"),
            (0x1005, "call 900 <malloc@plt>"),
            (0x100A, "mov %rax,-0x8(%rbp)"),
            (0x100D, "mov $0x100,%edx"),
            (0x1012, "mov %rax,%rsi"),
            (0x1015, "mov $0x0,%edi"),
            (0x1018, "call 910 <read@plt>"),
            (0x101D, "mov -0x8(%rbp),%rdx"),
            (0x1021, "mov $0x100,%eax"),
            (0x1026, "add %rdx,%rax"),
            (0x1029, "movb $0x0,(%rax)"),
        )
        self.assertEqual(
            vuln_points._off_by_one_points(
                {"name": "f"}, vuln_points.parse_instruction_lines(assembly),
                64, None, None), [])

    def test_off_by_one_confirmed_when_size_equals_usable(self):
        # malloc(0x18) → usable 0x18 == size → 终止符越界 → 报
        assembly = _lines(
            (0x1000, "mov $0x18,%edi"),
            (0x1005, "call 900 <malloc@plt>"),
            (0x100A, "mov %rax,-0x8(%rbp)"),
            (0x100D, "mov $0x18,%edx"),
            (0x1012, "mov %rax,%rsi"),
            (0x1015, "mov $0x0,%edi"),
            (0x1018, "call 910 <read@plt>"),
            (0x101D, "mov -0x8(%rbp),%rdx"),
            (0x1021, "mov $0x18,%eax"),
            (0x1026, "add %rdx,%rax"),
            (0x1029, "movb $0x0,(%rax)"),
        )
        points = vuln_points._off_by_one_points(
            {"name": "f"}, vuln_points.parse_instruction_lines(assembly),
            64, None, None)
        self.assertEqual([p["verdict"] for p in points], ["off_by_one_null_write"])
        self.assertIn("可用区", points[0]["reason"])


class ArrayIndexTests(TestCase):
    # 三个相邻数组基址：0x4b80 让 0x4b00 也有可推断的容量（合成 fixture
    # 没有 ELF，拿不到段末尾回退，必须靠邻居给出上界）。
    ARRAY_BASES = {0x4A80, 0x4B00, 0x4B80}

    def _extent(self, base, stride=8, objects=None):
        return vuln_points._array_extent(None, base, stride, self.ARRAY_BASES, objects)

    def test_extent_from_adjacent_array_base(self):
        self.assertEqual(self._extent(0x4A80), (0x80, "相邻数组基址 0x4b00"))

    def test_extent_prefers_object_symbol(self):
        objects = [{"address": 0x4A80, "size": 0x40, "name": "tbl"}]
        extent, basis = self._extent(0x4A80, objects=objects)
        self.assertEqual(extent, 0x40)
        self.assertIn("tbl", basis)

    def test_extent_none_without_any_basis(self):
        self.assertIsNone(vuln_points._array_extent(None, 0x9000, 8, set(), None))

    def test_off_by_one_when_guard_admits_past_end(self):
        # cmp $0x10,%eax; jg error → 放行 idx==16；数组 16 个元素(0..15)
        assembly = _lines(
            (0x1816, "mov 0x33e4(%rip),%eax        # 4c00"),
            (0x181C, "cmp $0x10,%eax"),
            (0x181F, "jg 1961 <err>"),
            (0x1825, "lea -0x50(%rbp),%rax"),
            (0x1829, "call 11a0 <strlen@plt>"),
            (0x1831, "cmp $0x6,%rax"),
            (0x1835, "jbe 1961 <err>"),
            (0x183B, "mov 0x33bf(%rip),%eax        # 4c00"),
            (0x1841, "cltq"),
            (0x1843, "lea 0x0(,%rax,8),%rdx"),
            (0x184B, "lea 0x322e(%rip),%rax        # 4a80"),
            (0x1852, "add %rdx,%rax"),
        )
        points = vuln_points._array_index_points(
            {"name": "touch"}, vuln_points.parse_instruction_lines(assembly),
            64, self.ARRAY_BASES, None, None)
        self.assertEqual([p["verdict"] for p in points], ["array_index_off_by_one"])
        self.assertEqual(points[0]["severity"], "critical")

    def test_correct_bound_is_not_reported(self):
        # 上界 0xf 恰好是最后一个合法下标 → 不报
        assembly = _lines(
            (0x1000, "mov 0x1000(%rip),%eax        # 4c00"),
            (0x1006, "cmp $0xf,%eax"),
            (0x1009, "jg 1010 <err>"),
            (0x100B, "mov 0x1000(%rip),%eax        # 4c00"),
            (0x1011, "cltq"),
            (0x1012, "lea 0x0(,%rax,8),%rdx"),
            (0x101A, "lea 0x3060(%rip),%rax        # 4a80"),
            (0x1021, "add %rdx,%rax"),
        )
        self.assertEqual(
            vuln_points._array_index_points(
                {"name": "f"}, vuln_points.parse_instruction_lines(assembly),
                64, self.ARRAY_BASES, None, None),
            [])

    def test_unchecked_input_index_is_reported_when_global_array_extent_is_known(self):
        assembly = _lines(
            (0x1000, "lea -0x4(%rbp),%rax"),
            (0x1004, "mov %rax,%rsi"),
            (0x1007, "call 1100 <__isoc99_scanf@plt>"),
            (0x100C, "mov -0x4(%rbp),%eax"),
            (0x100F, "cltq"),
            (0x1011, "lea 0x0(,%rax,8),%rdx"),
            (0x1019, "lea 0x3060(%rip),%rax        # 4a80"),
            (0x1020, "mov (%rdx,%rax,1),%rax"),
        )
        points = vuln_points._array_index_points(
            {"name": "show"}, vuln_points.parse_instruction_lines(assembly),
            64, self.ARRAY_BASES, None, None)
        self.assertEqual([p["verdict"] for p in points], ["array_index_unchecked"])
        self.assertEqual(points[0]["severity"], "high")

    def test_signed_bypass_requires_input_and_no_lower_bound(self):
        base = _lines(
            (0x1AA3, "call 1210 <read@plt>"),
            (0x1AAF, "call 1270 <atoi@plt>"),
            (0x1AB4, "mov %eax,-0x58(%rbp)"),
            (0x1AB7, "mov -0x58(%rbp),%eax"),
            (0x1ABA, "cmp $0xf,%eax"),
            (0x1ABD, "jg 1b33 <err>"),
            (0x1AD3, "mov -0x58(%rbp),%eax"),
            (0x1AD6, "cltq"),
            (0x1AD8, "lea 0x0(,%rax,8),%rdx"),
            (0x1AE0, "lea 0x3019(%rip),%rax        # 4b00"),
            (0x1AE7, "mov (%rdx,%rax,1),%rax"),
        )
        points = vuln_points._array_index_points(
            {"name": "edit"}, vuln_points.parse_instruction_lines(base),
            64, self.ARRAY_BASES, None, None)
        self.assertEqual([p["verdict"] for p in points], ["array_index_signed_bypass"])

    def test_lower_bound_check_suppresses_signed_bypass(self):
        guarded = _lines(
            (0x1AA3, "call 1270 <atoi@plt>"),
            (0x1AB4, "mov %eax,-0x58(%rbp)"),
            (0x1AB7, "mov -0x58(%rbp),%eax"),
            (0x1ABA, "test %eax,%eax"),
            (0x1ABC, "js 1b33 <err>"),
            (0x1ABE, "cmp $0xf,%eax"),
            (0x1AC1, "jg 1b33 <err>"),
            (0x1AD3, "mov -0x58(%rbp),%eax"),
            (0x1AD6, "cltq"),
            (0x1AD8, "lea 0x0(,%rax,8),%rdx"),
            (0x1AE0, "lea 0x3019(%rip),%rax        # 4b00"),
            (0x1AE7, "mov (%rdx,%rax,1),%rax"),
        )
        self.assertEqual(
            vuln_points._array_index_points(
                {"name": "edit"}, vuln_points.parse_instruction_lines(guarded),
                64, self.ARRAY_BASES, None, None),
            [])


class CommentStrippingTests(TestCase):
    def test_rip_load_with_comment_resolves_to_global(self):
        # 不剥注释时 dst_reg 会变成 "%eax # 4c00 <...>"，定义链断裂
        assembly = _lines(
            (0x1816, "mov 0x33e4(%rip),%eax        # 4c00 <stderr+0xb00>"),
            (0x181C, "cmp $0x10,%eax"),
        )
        lines = vuln_points.parse_instruction_lines(assembly)
        chain = vuln_points._backtrack(lines, 1, "eax")
        self.assertEqual(chain["kind"], "rip")
        self.assertEqual(chain["address"], 0x4C00)
