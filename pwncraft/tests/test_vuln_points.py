"""漏洞点确认单测：长度 vs 缓冲区边界的判定 golden（纯 AT&T 文本 fixture，无 WSL）。"""
from unittest import TestCase
from unittest.mock import patch

from pwncraft.features.synth.vuln_points import scan_functions
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
