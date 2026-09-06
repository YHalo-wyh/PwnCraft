"""Phase 4-8 core tests: libc facts, fmt lab, capabilities, heap stages."""
from __future__ import annotations

import unittest

from pwncraft.core.capability import analyze_capabilities, available_paths
from pwncraft.core.cli_runner import CliExecution, CliToolService
from pwncraft.core.fmtlab import find_fmt_offset, plan_fmt_writes, to_pwntools
from pwncraft.core.libc import (
    OneGadget,
    check_one_gadget_constraints,
    parse_build_id,
    parse_one_gadget_output,
)
from pwncraft.core.workspace import PwnWorkspace


_ONE_GADGET_OUTPUT = """0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [1] r15 == NULL
  [2] r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [1] r15 == NULL
  [2] rdx == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [1] rsp & 0xf == 0
  [2] rcx == NULL"""


class LibcFactsTests(unittest.TestCase):
    def test_one_gadget_parsing_keeps_all_constraints(self) -> None:
        gadgets = parse_one_gadget_output(_ONE_GADGET_OUTPUT)
        self.assertEqual(len(gadgets), 3)
        self.assertEqual(gadgets[0].address, 0xE3AFE)
        self.assertEqual(len(gadgets[0].constraints), 2)
        # masked-rsp constraint is preserved, then judged unknown at check time
        self.assertEqual(len(gadgets[2].constraints), 2)

    def test_constraint_check_registry_only(self) -> None:
        gadget = parse_one_gadget_output(_ONE_GADGET_OUTPUT)[0]
        report = check_one_gadget_constraints(gadget, {"r15": 0, "r12": 0})
        self.assertTrue(report.usable)
        report_violated = check_one_gadget_constraints(gadget, {"r15": 0, "r12": 5})
        self.assertFalse(report_violated.usable)
        self.assertEqual(len(report_violated.violated), 1)
        report_unknown = check_one_gadget_constraints(gadget, {"r15": 0})
        self.assertFalse(report_unknown.usable)
        self.assertEqual(len(report_unknown.unknown), 1)

    def test_memory_constraints_never_become_usable_without_oracle(self) -> None:
        masked = parse_one_gadget_output(_ONE_GADGET_OUTPUT)[2]
        report = check_one_gadget_constraints(masked, {"rsp": 0, "rcx": 0})
        self.assertFalse(report.usable)
        self.assertTrue(any("rsp" in item for item in report.unknown))

    def test_build_id_extraction(self) -> None:
        self.assertEqual(parse_build_id("  Build ID: deadbeefcafebabe1234567890abcdef12345678"), "deadbeefcafebabe1234567890abcdef12345678")
        self.assertEqual(parse_build_id("no notes here"), "")

    def test_one_gadget_query_lands_in_libraries(self) -> None:
        class Fake:
            def execute(self, executable, argv):
                return CliExecution("one_gadget", executable, tuple(argv), "one_gadget", 0, _ONE_GADGET_OUTPUT, "")

        workspace = PwnWorkspace()
        outcome = CliToolService(Fake()).run_and_apply(workspace, "one_gadget", {"libc": "./libc.so.6"})
        self.assertTrue(outcome.ok)
        gadgets = workspace.libraries["one_gadgets"]
        self.assertEqual(len(gadgets), 3)
        self.assertIn("one_gadget", str(workspace.libraries["one_gadgets_source"]))


class FmtLabTests(unittest.TestCase):
    def test_offset_finder_64_and_32_bit(self) -> None:
        self.assertEqual(find_fmt_offset("0x1 0x7f2 0x4141414141414141 0x5"), 3)
        self.assertEqual(find_fmt_offset("0x1 0x41414141 0x3"), 2)
        self.assertIsNone(find_fmt_offset("0x1 0x2"))
        self.assertEqual(find_fmt_offset("0x41414141 0x2", bits=32), 1)

    def test_write_plan_decomposition_is_exact(self) -> None:
        plan = plan_fmt_writes(0x404018, 0x401216)
        self.assertEqual(plan.parts[0], (0x404018, 0x1216))
        self.assertEqual(plan.parts[1], (0x40401A, 0x40))
        self.assertEqual(plan.write_size, "short")
        recombined = sum(part << (8 * index * 2) for index, (_addr, part) in enumerate(plan.parts))
        self.assertEqual(recombined, 0x401216)

    def test_write_plan_rejects_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            plan_fmt_writes(-1, 0x10)
        with self.assertRaises(ValueError):
            plan_fmt_writes(0x10, 1 << 70)

    def test_pwntools_skeleton_delegates_payload_math(self) -> None:
        plan = plan_fmt_writes(0x404018, 0x401216)
        code = to_pwntools(plan, offset=8)
        self.assertIn("fmtstr_payload(8", code)
        self.assertIn("write_size='short'", code)


class CapabilityTests(unittest.TestCase):
    def _workspace(self) -> PwnWorkspace:
        workspace = PwnWorkspace()
        workspace.set_binary(path="./pwn", bits=64, architecture="amd64", security={"NX": "ON"})
        return workspace

    def test_empty_workspace_has_no_available_paths(self) -> None:
        capabilities = analyze_capabilities(PwnWorkspace())
        self.assertEqual(available_paths(PwnWorkspace()), ())
        self.assertTrue(all(item.state != "available" for item in capabilities))

    def test_ret2libc_path_from_real_facts(self) -> None:
        workspace = self._workspace()
        workspace.set_gadgets([{"instructions": ["pop", "ret"], "controls": ["rdi"]}], source="t")
        workspace.symbols.update({"got": {"puts": 0x404018}, "plt": {"puts": 0x401020}})
        workspace.set_libc_base(0x7F000000, formula="0x7f000420 - 0x420", source="derived")
        capabilities = {item.name: item for item in analyze_capabilities(workspace)}
        self.assertEqual(capabilities["ret2libc"].state, "available")
        self.assertIn("ret2libc", available_paths(workspace))

    def test_orw_available_only_when_seccomp_blocks_execve(self) -> None:
        workspace = self._workspace()
        workspace.set_seccomp_policy({"execve": "BLOCKED", "open": "ALLOWED", "read": "ALLOWED", "write": "ALLOWED"}, source="t")
        self.assertIn("ORW", available_paths(workspace))
        workspace2 = self._workspace()
        workspace2.set_seccomp_policy({"execve": "ALLOWED"}, source="t")
        caps = {item.name: item for item in analyze_capabilities(workspace2)}
        self.assertNotEqual(caps["ORW"].state, "available")

    def test_control_rip_requires_evidence(self) -> None:
        workspace = self._workspace()
        caps = {item.name: item for item in analyze_capabilities(workspace)}
        self.assertEqual(caps["Control RIP"].state, "unknown")
        workspace.stack["overflow_offset"] = 72
        caps = {item.name: item for item in analyze_capabilities(workspace)}
        self.assertEqual(caps["Control RIP"].state, "available")

    def test_primitive_records(self) -> None:
        workspace = PwnWorkspace()
        record = workspace.add_primitive("Control RIP", evidence="offset 72", source="stack page")
        self.assertEqual(record["name"], "Control RIP")
        workspace.add_primitive("Control RIP", evidence="updated")
        primitives = workspace.exploit["primitives"]
        self.assertEqual(len(primitives), 1)
        self.assertEqual(primitives[0]["evidence"], "updated")


class HeapStageTests(unittest.TestCase):
    def test_record_heap_stage_dedupes_by_step(self) -> None:
        workspace = PwnWorkspace()
        first = workspace.record_heap_stage({"step": 3, "event_title": "free chunk0"}, title="free chunk0")
        self.assertIsNotNone(first)
        self.assertIsNone(workspace.record_heap_stage({"step": 3, "event_title": "free chunk0"}))
        workspace.record_heap_stage({"step": 4, "event_title": "malloc"})
        heap_stages = [item for item in workspace.exploit["stages"] if item.get("type") == "heap"]
        self.assertEqual(len(heap_stages), 2)
        self.assertEqual(heap_stages[0]["inputs"]["step"], 3)


class LibcWorkspaceApiTests(unittest.TestCase):
    def test_set_libc_symbols_sanitizes_entries(self) -> None:
        workspace = PwnWorkspace()
        events: list[dict[str, object]] = []
        workspace.subscribe("libc_symbols_changed", events.append)
        workspace.set_libc_symbols({"system": "0x52290", "bad": "not-a-number"}, source="readelf")
        self.assertEqual(workspace.libraries["libc_symbols"], {"system": 0x52290})
        self.assertEqual(events[-1]["count"], 1)


if __name__ == "__main__":
    unittest.main()
