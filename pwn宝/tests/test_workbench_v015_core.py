"""v0.15 Workbench core tests: CLI service, static parsers, palette, shelf."""
from __future__ import annotations

import unittest

from pwnbao.core.cli_runner import CliExecution, CliToolService
from pwnbao.core.cli_registry import default_cli_tools
from pwnbao.core.static_facts import (
    parse_objdump_plt,
    parse_objdump_relocations,
    parse_readelf_dynsyms,
)
from pwnbao.core.workbench import default_palette_entries, search_palette
from pwnbao.core.workspace import PwnWorkspace


class FakeExecutor:
    """Offline executor: it records argv and replays canned stdout."""

    def __init__(self, output: str = "", returncode: int = 0):
        self.output = output
        self.returncode = returncode
        self.calls: list[tuple[str, list[str]]] = []

    def execute(self, executable: str, argv: list[str]) -> CliExecution:
        self.calls.append((executable, list(argv)))
        return CliExecution(
            "",
            executable,
            tuple(argv),
            " ".join([executable, *argv]),
            self.returncode,
            self.output,
            "",
        )


_DYNSYMS = """Symbol table '.dynsym' contains 5 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.2.5 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND system@GLIBC_2.2.5 (3)
     3: 0000000000112069    97 FUNC    GLOBAL DEFAULT   16 main
     4: 0000000000404060     8 OBJECT  GLOBAL DEFAULT   24 stdout@GLIBC_2.2.5"""

_RELOCS = """DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
0000000000404018 R_X86_64_GLOB_DAT  puts
0000000000404020 R_X86_64_JUMP_SLOT  printf
0000000000404028 R_X86_64_RELATIVE  *ABS*"""

_PLT = """Disassembly of section .plt:

0000000000401020 <puts@plt>:
    401020: ff 25 fa 2f 00 00    jmpq   *0x2ffa(%rip)

0000000000401030 <printf@plt>:
    401030: ff 25 fa 2f 00 00    jmpq   *0x2ffa(%rip)"""


class StaticParserTests(unittest.TestCase):
    def test_readelf_dynsyms_separates_functions_imports_objects(self) -> None:
        facts = parse_readelf_dynsyms(_DYNSYMS)
        self.assertEqual(facts.functions, {"main": 0x112069})
        self.assertEqual(facts.imports, ("puts", "system"))
        self.assertEqual(facts.objects, {"stdout": 0x404060})

    def test_objdump_relocations_maps_got_slots_and_skips_relative(self) -> None:
        got = parse_objdump_relocations(_RELOCS)
        self.assertEqual(got, {"puts": 0x404018, "printf": 0x404020})

    def test_objdump_plt_extracts_stub_addresses(self) -> None:
        plt = parse_objdump_plt(_PLT)
        self.assertEqual(plt, {"puts": 0x401020, "printf": 0x401030})

    def test_parsers_reject_noise(self) -> None:
        noise = "just some random text\nwithout any structure"
        self.assertEqual(parse_readelf_dynsyms(noise).functions, {})
        self.assertEqual(parse_objdump_relocations(noise), {})
        self.assertEqual(parse_objdump_plt(noise), {})


class CliToolServiceTests(unittest.TestCase):
    def test_build_argv_maps_paths_and_flags(self) -> None:
        service = CliToolService(FakeExecutor())
        _executable, argv = service.build_argv("readelf.dynsyms", {"file": "./pwn"})
        self.assertEqual(argv, ["-sW", "./pwn"])
        _executable, argv = service.build_argv("checksec", {"file": "C:/work/pwn"})
        self.assertEqual(argv, ["--file=C:/work/pwn"])

    def test_gadget_query_publishes_structured_facts_with_evidence(self) -> None:
        workspace = PwnWorkspace()
        executor = FakeExecutor("0x4012c3 : pop rdi ; ret")
        service = CliToolService(executor)
        outcome = service.run_and_apply(workspace, "ropgadget", {"binary": "./pwn", "only": "pop|ret"}, bits=64, base=0x400000)
        self.assertTrue(outcome.ok)
        self.assertEqual(len(workspace.gadgets["discovered"]), 1)
        gadget = workspace.gadgets["discovered"][0]
        self.assertEqual(gadget["controls"], ["rdi"])
        self.assertEqual(gadget["relative_offset"], 0x12C3)
        self.assertIn("ROPgadget", gadget["source"])

    def test_checksec_updates_binary_security_with_source(self) -> None:
        workspace = PwnWorkspace()
        executor = FakeExecutor("CANARY: Not found\nNX: enabled\nPIE: No PIE\nRELRO: Full RELRO")
        service = CliToolService(executor)
        service.run_and_apply(workspace, "checksec", {"file": "./pwn"})
        self.assertEqual(workspace.binary["security"]["CANARY"], "OFF")
        self.assertEqual(workspace.binary["security"]["NX"], "ON")
        self.assertEqual(workspace.binary["security"]["RELRO"], "FULL")
        self.assertIn("checksec", str(workspace.binary["security_source"]))

    def test_symbol_facts_merge_into_symbols_section(self) -> None:
        workspace = PwnWorkspace()
        service = CliToolService(FakeExecutor(_DYNSYMS))
        service.run_and_apply(workspace, "readelf.dynsyms", {"file": "./pwn"})
        service.executor = FakeExecutor(_RELOCS)
        service.run_and_apply(workspace, "objdump.relocations", {"file": "./pwn"})
        service.executor = FakeExecutor(_PLT)
        service.run_and_apply(workspace, "objdump.plt", {"file": "./pwn"})
        self.assertEqual(workspace.symbols["functions"]["main"], 0x112069)
        self.assertEqual(workspace.symbols["got"]["puts"], 0x404018)
        self.assertEqual(workspace.symbols["plt"]["puts"], 0x401020)
        self.assertIn("puts", workspace.symbols["imports"])

    def test_seccomp_query_populates_global_policy(self) -> None:
        workspace = PwnWorkspace()
        executor = FakeExecutor("allow: openat\nallow: read\nblock execve")
        service = CliToolService(executor)
        service.run_and_apply(workspace, "seccomp-tools", {"file": "./pwn"})
        policy = workspace.syscalls["seccomp_policy"]
        self.assertEqual(policy.get("execve"), "BLOCKED")

    def test_query_tools_never_touch_exploit_state(self) -> None:
        workspace = PwnWorkspace()
        workspace.set_exploit_source("original = True\n")
        executor = FakeExecutor("0x4012c3 : pop rdi ; ret")
        service = CliToolService(executor)
        service.run_and_apply(workspace, "ropgadget", {"binary": "./pwn"}, bits=64)
        self.assertEqual(workspace.exploit["source"], "original = True\n")
        events: list[dict[str, object]] = []
        workspace.subscribe("exploit_source_changed", events.append)
        service.run_and_apply(workspace, "checksec", {"file": "./pwn"})
        self.assertEqual(events, [])

    def test_failed_execution_reports_error_and_publishes_nothing(self) -> None:
        workspace = PwnWorkspace()
        service = CliToolService(FakeExecutor("", returncode=1))
        outcome = service.run_and_apply(workspace, "ropgadget", {"binary": "./missing"})
        self.assertFalse(outcome.ok)
        self.assertEqual(workspace.gadgets["discovered"], [])

    def test_offline_service_refuses_execution_but_keeps_preview(self) -> None:
        service = CliToolService(None)
        with self.assertRaises(RuntimeError):
            service.execute_only("checksec", {"file": "./pwn"})
        self.assertEqual(service.build_command_line("ropgadget", {"binary": "./pwn", "only": "pop|ret"}), "ROPgadget --binary ./pwn --only 'pop|ret'")


class PaletteTests(unittest.TestCase):
    def test_title_hits_rank_above_description_hits(self) -> None:
        first = search_palette("gadget")[0]
        self.assertEqual(first.id, "gadget.search")
        self.assertEqual(search_palette("变量")[0].id, "workspace.variables")
        self.assertEqual(search_palette("libc")[0].id, "libc.workspace")

    def test_no_match_returns_empty_and_blank_returns_all(self) -> None:
        self.assertEqual(search_palette("zzz-no-match"), ())
        self.assertEqual(len(search_palette("")), len(default_palette_entries()))


class ShelfWorkspaceTests(unittest.TestCase):
    def test_unpin_removes_role_and_publishes_event(self) -> None:
        from pwnbao.core.gadgets import parse_gadget_line

        workspace = PwnWorkspace()
        events: list[dict[str, object]] = []
        workspace.subscribe("gadget_unpinned", events.append)
        gadget = parse_gadget_line("0x4012c3 : pop rdi ; ret")
        workspace.pin_gadget("rdi", gadget)
        workspace.unpin_gadget("RDI")
        self.assertEqual(workspace.gadgets["pinned"], [])
        self.assertEqual(events[-1]["role"], "rdi")
        self.assertIsNone(workspace.unpin_gadget("rdi"))


class MergeSavedTests(unittest.TestCase):
    def test_merge_restores_sections_and_keeps_identity(self) -> None:
        source = PwnWorkspace(project={"project_name": "case"})
        source.set_variable(
            __import__("pwnbao.core.workspace", fromlist=["WorkspaceVariable"]).WorkspaceVariable(
                "pop_rdi", 0x4012C3, "ROPgadget", "0x4012c3 : pop rdi ; ret"
            )
        )
        source.set_runtime(heap_base=0x55550000)
        payload = source.to_dict()
        live = PwnWorkspace()
        events: list[dict[str, object]] = []
        live.subscribe("workspace_merged", events.append)
        live.merge_saved(payload)
        self.assertIs(live, live)
        self.assertEqual(live.get_variable("pop_rdi").value, 0x4012C3)
        self.assertEqual(live.runtime["state"], "stale")
        self.assertEqual(events[-1]["event"] if "event" in events[-1] else "merged", "merged")


class CliRegistryTests(unittest.TestCase):
    def test_every_tool_declares_chinese_parameter_help(self) -> None:
        for tool in default_cli_tools().values():
            self.assertTrue(tool.description_zh, tool.id)
            for parameter in tool.parameters:
                self.assertTrue(parameter.get("description_zh"), f"{tool.id}:{parameter.get('name')}")

    def test_build_command_concatenates_equals_flags(self) -> None:
        tool = default_cli_tools().get("checksec")
        command = default_cli_tools().build_command(tool, {"file": "./pwn"})
        self.assertEqual(command, "checksec --file=./pwn")


if __name__ == "__main__":
    unittest.main()
