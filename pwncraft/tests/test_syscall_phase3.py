"""Phase 3 core tests: syscall facts, planner diagnosis, seccomp, ORW plan."""
from __future__ import annotations

import unittest

from pwncraft.core.gadgets import parse_gadget_line
from pwncraft.core.orw import ORWBuilder
from pwncraft.core.syscalls import (
    lookup_syscall,
    normalize_architecture,
    parse_seccomp_policy,
    parse_seccomp_policy_structured,
    seccomp_verdict,
    syscall_table,
)
from pwncraft.core.workbench import SyscallPlanner


def _full_gadgets() -> list:
    lines = (
        "0x4012c3 : pop rdi ; ret",
        "0x4012c1 : pop rsi ; pop r15 ; ret",
        "0x4012bf : pop rdx ; ret",
        "0x4012bb : pop rax ; ret",
        "0x401180 : syscall ; ret",
        "0x40101a : ret",
    )
    return [parse_gadget_line(line) for line in lines]


class SyscallTableTests(unittest.TestCase):
    def test_extended_entries_cover_three_architectures(self) -> None:
        self.assertEqual(lookup_syscall("execve", "x86_64").number, 59)
        self.assertEqual(lookup_syscall("mprotect", "amd64").number, 10)
        self.assertEqual(lookup_syscall("dup2", "amd64").number, 33)
        self.assertEqual(lookup_syscall("close", "i386").number, 6)
        self.assertEqual(lookup_syscall("mmap", "i386").name, "mmap2")
        self.assertEqual(lookup_syscall("close", "aarch64").number, 57)
        # aarch64 has no dup2: absence stays unknown instead of fabricated.
        self.assertIsNone(lookup_syscall("dup2", "aarch64"))

    def test_spec_roundtrip_and_return_register(self) -> None:
        spec = lookup_syscall("openat", "amd64")
        payload = spec.to_dict()
        self.assertEqual(payload["return_register"], "rax")
        restored = type(spec).from_dict(payload)
        self.assertEqual(restored, spec)
        self.assertEqual(lookup_syscall("read", "i386").return_register, "eax")

    def test_normalize_strict_rejects_unknown_architecture(self) -> None:
        self.assertEqual(normalize_architecture("arm64"), "aarch64")
        with self.assertRaises(ValueError):
            normalize_architecture("mips", strict=True)
        # compatibility default keeps amd64 fallback
        self.assertEqual(normalize_architecture("mips"), "amd64")


class SeccompTests(unittest.TestCase):
    def test_flat_parser_keeps_legacy_contract(self) -> None:
        policy = parse_seccomp_policy("allow: read\ndeny write\nopenat ALLOW\n# ignored")
        self.assertEqual(policy, {"read": "ALLOWED", "write": "BLOCKED", "openat": "ALLOWED"})

    def test_structured_parser_records_default_and_constraints(self) -> None:
        result = parse_seccomp_policy_structured("default action: kill\nallow: openat\nif (arg1 == 0x0) allow read")
        self.assertEqual(result["default_action"], "kill")
        self.assertEqual(result["policy"].get("openat"), "ALLOWED")
        self.assertIn("read", result["constraints"])
        self.assertTrue(any("arg1" in line for line in result["source_lines"]))

    def test_verdict_unknown_without_explicit_entry(self) -> None:
        policy = {"openat": "ALLOWED"}
        self.assertEqual(seccomp_verdict(policy, "openat"), "ALLOWED")
        self.assertEqual(seccomp_verdict(policy, "execve"), "UNKNOWN")


class PlannerDiagnosisTests(unittest.TestCase):
    def test_diagnose_full_gadgets_is_executable(self) -> None:
        plan = SyscallPlanner().diagnose(
            "read",
            {"fd": 0, "buf": 0x404800, "len": 0x100},
            gadgets=_full_gadgets(),
            seccomp_policy={"read": "ALLOWED"},
        )
        self.assertTrue(plan.complete)
        self.assertEqual(plan.registers["rsi"], 0x404800)
        self.assertEqual(plan.seccomp_verdict, "ALLOWED")
        self.assertTrue(plan.executable)

    def test_blocked_syscall_is_never_executable(self) -> None:
        plan = SyscallPlanner().diagnose(
            "execve",
            {"filename": "/bin/sh", "argv": 0, "envp": 0},
            gadgets=_full_gadgets(),
            seccomp_policy={"execve": "BLOCKED", "read": "ALLOWED"},
        )
        self.assertEqual(plan.seccomp_verdict, "BLOCKED")
        self.assertFalse(plan.executable)
        self.assertTrue(any("seccomp BLOCKED" in item for item in plan.blockers))

    def test_missing_gadget_blocks_execution_and_names_register(self) -> None:
        only_rdi = [parse_gadget_line("0x4012c3 : pop rdi ; ret")]
        plan = SyscallPlanner().diagnose(
            "read",
            {"fd": 0, "buf": 0x404800, "len": 0x100},
            gadgets=only_rdi,
            seccomp_policy={"read": "ALLOWED"},
        )
        self.assertFalse(plan.executable)
        # Argument coverage is complete; the gap is gadget control, which is
        # reported in blockers with the missing register names.
        self.assertEqual(plan.missing_registers, ())
        self.assertTrue(any("RSI" in item and "RDX" in item for item in plan.blockers))

    def test_unknown_seccomp_stays_unknown_not_allowed(self) -> None:
        plan = SyscallPlanner().diagnose(
            "read",
            {"fd": 0, "buf": 0x404800, "len": 0x100},
            gadgets=_full_gadgets(),
            seccomp_policy={},
        )
        self.assertEqual(plan.seccomp_verdict, "UNKNOWN")
        self.assertFalse(plan.executable)

    def test_plan_to_dict_is_json_safe(self) -> None:
        plan = SyscallPlanner().diagnose("write", {"fd": 1, "buf": 0x1000, "len": 8}, gadgets=_full_gadgets(), seccomp_policy={"write": "ALLOWED"})
        payload = plan.to_dict()
        self.assertEqual(payload["syscall"]["name"], "write")
        self.assertTrue(payload["executable"])


class ORWBuilderTests(unittest.TestCase):
    def test_full_policy_and_gadgets_yield_ok_plan(self) -> None:
        builder = ORWBuilder(bits=64, seccomp_policy={"openat": "ALLOWED", "read": "ALLOWED", "write": "ALLOWED"}, gadgets=_full_gadgets())
        report = builder.plan(path="/flag", buffer=0x404800, read_size=0x100, output_fd=1)
        self.assertTrue(report.ok, [s.blockers for s in report.steps])
        # auto prefers plain `open`: three controllable registers instead of
        # openat's extra r10, so the plan stays provable from real gadgets.
        self.assertEqual([step.syscall for step in report.steps], ["open", "read", "write"])

    def test_explicit_openat_requires_r10_control(self) -> None:
        builder = ORWBuilder(bits=64, seccomp_policy={"openat": "ALLOWED", "read": "ALLOWED", "write": "ALLOWED"}, gadgets=_full_gadgets())
        report = builder.plan(open_variant="openat")
        self.assertFalse(report.ok)
        self.assertTrue(any("R10" in item for item in report.steps[0].blockers))

    def test_blocked_open_makes_plan_not_ok(self) -> None:
        builder = ORWBuilder(bits=64, seccomp_policy={"open": "BLOCKED", "openat": "BLOCKED", "read": "ALLOWED", "write": "ALLOWED"}, gadgets=_full_gadgets())
        report = builder.plan()
        self.assertFalse(report.ok)
        self.assertTrue(any("seccomp BLOCKED" in item for item in report.steps[0].blockers))

    def test_missing_gadget_blocks_read_step(self) -> None:
        builder = ORWBuilder(bits=64, seccomp_policy={"openat": "ALLOWED", "read": "ALLOWED", "write": "ALLOWED"}, gadgets=[parse_gadget_line("0x4012c3 : pop rdi ; ret")])
        report = builder.plan()
        self.assertFalse(report.ok)
        self.assertTrue(any("缺少控制 Gadget" in item for item in report.steps[1].blockers))

    def test_dynamic_fd_placeholder_is_inferred(self) -> None:
        builder = ORWBuilder(bits=64, seccomp_policy={"open": "ALLOWED", "openat": "ALLOWED", "read": "ALLOWED", "write": "ALLOWED"}, gadgets=_full_gadgets())
        report = builder.plan()
        read_step = report.steps[1]
        self.assertIn("fd=OPEN_FD", read_step.inferred_fields)
        # The alias resolves to the arch register; the placeholder value marks
        # the dependency on open's return value.
        self.assertEqual(read_step.registers[read_step.missing_registers[0]] if read_step.missing_registers else read_step.registers["rdi"], "OPEN_FD")

    def test_report_to_dict_is_json_safe(self) -> None:
        builder = ORWBuilder(bits=64, seccomp_policy={"openat": "ALLOWED", "read": "ALLOWED", "write": "ALLOWED"}, gadgets=_full_gadgets())
        payload = builder.plan().to_dict()
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["steps"]), 3)
        self.assertIn("inferred_fields", payload["steps"][1])


if __name__ == "__main__":
    unittest.main()
