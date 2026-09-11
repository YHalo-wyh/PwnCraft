"""漏洞点确认单测：长度 vs 缓冲区边界的判定 golden（纯 AT&T 文本 fixture，无 WSL）。"""
from unittest import TestCase

from pwncraft.features.synth.vuln_points import scan_functions


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

    def test_sorting_puts_confirmed_first(self):
        points = scan_functions([{"name": "main", "assembly": VULN_MAIN}])
        self.assertEqual(points[0]["verdict"], "overflow_confirmed")

    def test_empty_input(self):
        self.assertEqual(scan_functions([]), [])
        self.assertEqual(scan_functions([{"name": "f", "assembly": ""}]), [])
