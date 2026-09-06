from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pwncraft.core.cli_registry import default_cli_tools
from pwncraft.core.gadgets import GadgetShelf, parse_gadget_line, parse_ropgadget_output, search_gadgets
from pwncraft.core.rop import ROPChain, RegisterState, StackState
from pwncraft.core.workbench import SyscallPlanner, encode_value, parse_checksec_output, search_palette
from pwncraft.core.syscalls import lookup_syscall, parse_seccomp_policy
from pwncraft.core.tool_actions import ActionType, ToolAction, ToolActionRegistry, default_tool_actions
from pwncraft.core.truth_providers import ELFProvider
from pwncraft.core.workspace import AddressKind, PwnWorkspace, TypedAddress, WorkspaceVariable


class WorkbenchCoreTests(unittest.TestCase):
    def test_action_registry_is_case_insensitive_and_query_is_read_only(self) -> None:
        action = ToolAction("example", "Example", "query", frozenset({"RUN", "copy_value"}))
        self.assertEqual(action.action_type, ActionType.QUERY)
        self.assertTrue(action.allows("run"))
        with self.assertRaises(ValueError):
            ToolActionRegistry((ToolAction("bad", "bad", ActionType.QUERY, frozenset({"insert_to_exp"})),))
        registry = default_tool_actions()
        self.assertFalse(registry.can("ropgadget.search", "insert_to_exp"))
        self.assertTrue(registry.can("rop.build", "insert_to_exp"))

    def test_workspace_roundtrip_preserves_typed_variable_and_marks_runtime_stale(self) -> None:
        workspace = PwnWorkspace(project={"project_name": "demo"})
        workspace.set_binary(path="./pwn", bits=64, architecture="amd64")
        workspace.set_runtime(heap_base=0x55550000)
        workspace.set_variable(WorkspaceVariable("pop_rdi", TypedAddress(0x4012C3, AddressKind.GADGET_ADDRESS), "ROPgadget", "raw line"))
        events: list[dict[str, object]] = []
        workspace.subscribe("variable_changed", events.append)
        workspace.set_variable(WorkspaceVariable("libc_base", 0x7F000000, "derived", formula="puts_leak - puts"))
        self.assertEqual(events[-1]["name"], "libc_base")
        with TemporaryDirectory() as temporary:
            path = workspace.save(Path(temporary) / "case")
            self.assertTrue(path.name.endswith(".pwncraft"))
            loaded = PwnWorkspace.load(path)
        self.assertEqual(loaded.binary["bits"], 64)
        self.assertEqual(loaded.get_variable("pop_rdi").value.value, 0x4012C3)
        self.assertEqual(loaded.get_variable("pop_rdi").value.kind, AddressKind.GADGET_ADDRESS)
        self.assertEqual(loaded.runtime["state"], "stale")

    def test_workspace_tracks_editable_exp_source_by_hash(self) -> None:
        workspace = PwnWorkspace()
        events: list[dict[str, object]] = []
        workspace.subscribe("exploit_source_changed", events.append)
        workspace.set_exploit_source("add(0x20, b'A')\n")
        workspace.set_exploit_source("add(0x20, b'A')\n")
        self.assertEqual(workspace.exploit["source"], "add(0x20, b'A')\n")
        self.assertEqual(len(workspace.exploit["source_hash"]), 64)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["length"], len("add(0x20, b'A')\n"))

    def test_workspace_tracks_heap_snapshot_as_a_json_safe_projection(self) -> None:
        workspace = PwnWorkspace()
        events: list[dict[str, object]] = []
        workspace.subscribe("heap_changed", events.append)
        workspace.set_heap_snapshot(
            {
                "step": 2,
                "chunks": {"chunk_0": {"address": "0x1000", "chunk_size": "0x70"}},
                "bins": {"tcache": {"0x70": ("chunk_0",)}},
            },
            origin="STATIC",
        )
        self.assertEqual(workspace.heap["step"], 2)
        self.assertEqual(workspace.heap["bins"]["tcache"]["0x70"], ["chunk_0"])
        self.assertEqual(workspace.heap["origin"], "STATIC")
        self.assertEqual(events[-1]["step"], 2)

    def test_gadget_parser_and_shelf(self) -> None:
        single = parse_gadget_line("0x4012c3 : pop rdi ; ret", source="./pwn", base=0x400000)
        multi = parse_gadget_line("0x4012c1 : pop rdi ; pop rbp ; ret")
        self.assertIsNotNone(single)
        self.assertEqual(single.controls, ("rdi",))
        self.assertEqual(single.stack_delta, 0x10)
        self.assertEqual(single.relative_offset, 0x12C3)
        self.assertEqual(single.score, 5)
        self.assertEqual(multi.controls, ("rdi", "rbp"))
        gadgets = parse_ropgadget_output("0x1 : pop rdi ; ret\n0x2 : syscall ; ret\n0x1 : pop rdi ; ret")
        self.assertEqual(len(gadgets), 2)
        self.assertEqual(len(search_gadgets(gadgets, "pop rdi")), 1)
        shelf = GadgetShelf()
        shelf.pin("RDI", single)
        self.assertIs(shelf.get("rdi"), single)
        self.assertIs(shelf.unpin("rdi"), single)

    def test_rop_register_simulation_handles_duplicate_entries(self) -> None:
        gadget = parse_gadget_line("0x4012c3 : pop rdi ; ret")
        chain = ROPChain()
        chain.append(0x4012C3, kind="gadget", gadget=gadget)
        chain.append(0x404018)
        chain.append(0x4012C3, kind="gadget", gadget=gadget)
        chain.append(0x404020)
        state, trace = chain.simulate(initial_rsp=0x1000, initial=RegisterState())
        self.assertEqual(state.get("rdi"), 0x404020)
        self.assertEqual(len(trace), 4)
        self.assertEqual(chain.check_alignment(initial_rsp=0x1008).rsp_mod_16, 8)

    def test_syscall_tables_and_seccomp_policy(self) -> None:
        self.assertEqual(lookup_syscall("execve", "x86_64").number, 59)
        self.assertEqual(lookup_syscall("read", "arm64").number, 63)
        policy = parse_seccomp_policy("allow: read\ndeny write\nopenat ALLOW\n# ignored")
        self.assertEqual(policy, {"read": "ALLOWED", "write": "BLOCKED", "openat": "ALLOWED"})
        plan = SyscallPlanner().plan("read", {"fd": 0, "buf": 0x404800, "len": 0x100})
        self.assertTrue(plan.complete)
        self.assertEqual(plan.registers["rsi"], 0x404800)

    def test_encoding_and_palette_are_deterministic(self) -> None:
        result = encode_value("0x7f", word_size=2)
        self.assertEqual(result.hex_bytes, "7f 00")
        self.assertEqual(result.python_expression, "p16(0x7f)")
        self.assertEqual(encode_value("b'AB'").packed, b"AB")
        with self.assertRaises(ValueError):
            encode_value(-1, word_size=8)
        with self.assertRaises(ValueError):
            encode_value(0x100, word_size=1)
        self.assertEqual(search_palette("gadget")[0].id, "gadget.search")
        self.assertEqual(search_palette("变量")[0].id, "workspace.variables")
        self.assertEqual(parse_checksec_output("RELRO: Full RELRO  NX: enabled  PIE: No PIE"), {"RELRO": "FULL", "NX": "ON", "PIE": "OFF"})

    def test_checksec_negative_forms_are_bounded_to_their_field(self) -> None:
        output = "CANARY: Not found  NX: enabled  PIE: No PIE"
        self.assertEqual(parse_checksec_output(output), {"CANARY": "OFF", "NX": "ON", "PIE": "OFF"})
        self.assertEqual(parse_checksec_output("FORTIFY: Enabled"), {"FORTIFY": "ON"})
        self.assertEqual(parse_checksec_output("RELRO: No RELRO\nNX: disabled"), {"RELRO": "NONE", "NX": "OFF"})
        self.assertEqual(parse_checksec_output("Stack: No canary found\nNX: NX enabled"), {"CANARY": "OFF", "NX": "ON"})

    def test_stack_state_tracks_word_addresses(self) -> None:
        stack = StackState(0x7000)
        self.assertEqual(stack.push(0x401000), 0x7000)
        self.assertEqual(stack.push("pop rdi"), 0x7008)
        self.assertEqual(stack.read(0x7008), "pop rdi")

    def test_cli_registry_builds_quoted_command_and_serializes(self) -> None:
        registry = default_cli_tools()
        tool = registry.get("ropgadget")
        command = registry.build_command(tool, {"binary": "C:/work dir/pwn", "only": "pop|ret", "badbytes": "000a"})
        self.assertIn("--binary", command)
        self.assertIn("'C:/work dir/pwn'", command)
        self.assertIn("--only 'pop|ret'", command)
        self.assertTrue(registry.values())
        self.assertTrue(registry.to_dict())

    def test_elf_provider_reads_header_without_guessing_invalid_class(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "pwn"
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = (0x3E).to_bytes(2, "little")
            header[24:32] = (0x401000).to_bytes(8, "little")
            path.write_bytes(header)
            provider = ELFProvider(path)
            self.assertEqual(provider.query("bits").value, 64)
            self.assertEqual(provider.query("architecture").value, "amd64")
            self.assertEqual(provider.query("entry").value, 0x401000)


if __name__ == "__main__":
    unittest.main()
