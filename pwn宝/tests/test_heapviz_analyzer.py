from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pwnbao.features.heapviz import (
    BehaviorEffect,
    ChallengeBehaviorProfile,
    ChallengeCallBehavior,
    HeapOperation,
    HeapOperationKind,
    HeapScenario,
    TimelineOverride,
    analyze_heap_source,
    build_allocator_config,
)
from pwnbao.features.heapviz.engine import GlibcHeapEngine


class HeapVizAnalyzerTests(unittest.TestCase):
    def test_zero_arg_free_uses_last_allocated_implicit_handle(self) -> None:
        source = '''
def create(payload):
    pass

def delete():
    pass

create(b"A")
delete()
delete()
'''
        result = analyze_heap_source(source)

        self.assertEqual(
            [operation.kind for operation in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.FREE, HeapOperationKind.FREE],
        )
        self.assertEqual(result.operations[0].index, "0")
        self.assertEqual(result.operations[1].index, "0")
        self.assertEqual(result.operations[1].chunk, result.operations[0].chunk)
        self.assertEqual(result.operations[2].index, "0")

    def test_three_arg_alloc_does_not_override_proven_size_and_data_roles(self) -> None:
        source = '''
def add(size, content, lenth):
    io.sendline(str(size))
    io.send(content)
    io.sendline(lenth)

add(0x68, p64(target), "123")
'''
        result = analyze_heap_source(source)

        self.assertEqual(len(result.operations), 1)
        operation = result.operations[0]
        self.assertEqual(operation.kind, HeapOperationKind.ALLOC)
        self.assertEqual(operation.index, "0")
        self.assertEqual(operation.request_size, "0x68")
        self.assertEqual(operation.data, "p64(target)")

    def test_unique_uninvoked_exploit_is_previewed_as_inferred(self) -> None:
        source = '''
def add(size, data):
    pass

def delete(index):
    pass

def exploit():
    add(0x30, b"A")
    delete(0)
'''
        result = analyze_heap_source(source)

        self.assertEqual(
            [operation.kind for operation in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.FREE],
        )
        self.assertTrue(all(binding.confidence == "inferred" for binding in result.bindings))
        self.assertTrue(
            all(operation.meta.get("entrypoint_preview") == "uninvoked" for operation in result.operations)
        )
        self.assertIn("previewed_uninvoked_entrypoint", {item.code for item in result.diagnostics})

    def test_uninvoked_entry_preview_requires_one_unambiguous_entry(self) -> None:
        source = '''
def add(size, data):
    pass

def exploit():
    add(0x20, b"A")

def solve():
    add(0x30, b"B")
'''
        result = analyze_heap_source(source)

        self.assertFalse(result.operations)
        self.assertNotIn("previewed_uninvoked_entrypoint", {item.code for item in result.diagnostics})

    def test_recv_prompt_menu_helpers_are_not_value_parsers(self) -> None:
        source = '''
def create_heap(size, content):
    io.recvuntil(b"choice:")
    io.sendline(b"1")
    io.recvuntil(b"size:")
    io.sendline(str(size))
    io.recvuntil(b"content:")
    io.sendline(content)

def edit_heap(idx, size, content):
    io.recvuntil(b"choice:")
    io.sendline(b"2")
    io.sendline(str(idx))
    io.sendline(str(size))
    io.sendline(content)

def delete_heap(idx):
    io.recvuntil(b"choice:")
    io.sendline(b"3")
    io.sendline(str(idx))

create_heap(0x88, b"A")
edit_heap(0, 0x90, b"B")
delete_heap(0)
'''
        result = analyze_heap_source(source)

        self.assertTrue(result.valid)
        self.assertEqual(
            [operation.kind for operation in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.EDIT, HeapOperationKind.FREE],
        )
        self.assertEqual(result.operations[0].request_size, "0x88")
        self.assertEqual(result.operations[0].data, "b\"A\"")
        self.assertEqual(result.operations[1].index, "0")
        self.assertEqual(result.operations[1].data, "b\"B\"")

    def test_choice_prompt_does_not_turn_payload_only_menu_into_free(self) -> None:
        source = '''
def create(payload):
    io.sendlineafter(b"choice: ", enc(1))
    io.sendline(payload)

def delete():
    io.sendlineafter(b"choice: ", enc(2))

def sendMessage(payload):
    io.sendlineafter(b"choice: ", enc(3))
    io.sendline(payload)

create(b"A")
sendMessage(b"hello")
delete()
'''
        result = analyze_heap_source(source)

        self.assertEqual(
            [operation.kind for operation in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.FREE],
        )
        self.assertEqual(result.operations[0].data, "b\"A\"")
        self.assertEqual(result.operations[1].index, "0")
        self.assertTrue(all("sendMessage" not in binding.source_text for binding in result.bindings))

    def test_menu_choice_helpers_infer_free_copy_and_show_without_ai(self) -> None:
        source = '''
def do4(slot):
    io.sendlineafter(b"choice:", b"4")
    io.sendline(str(slot))

def do7(a, b, n):
    io.sendlineafter(b"choice:", b"7")
    io.sendline(str(a))
    io.sendline(str(b))
    io.sendline(str(n))

def do3(slot):
    io.sendlineafter(b"choice:", b"3")
    io.sendline(str(slot))
    return io.recvline(timeout=0.3)

add(0x20, 0)
add(0x20, 1)
do4(0)
do7(1, 0, 0x18)
do3(1)
'''
        result = analyze_heap_source(source)

        self.assertEqual(
            [operation.kind for operation in result.operations],
            [
                HeapOperationKind.ALLOC,
                HeapOperationKind.ALLOC,
                HeapOperationKind.FREE,
                HeapOperationKind.COPY,
                HeapOperationKind.SHOW,
            ],
        )
        self.assertEqual(result.operations[2].index, "0")
        self.assertEqual(result.operations[3].meta["src"], "1")
        self.assertEqual(result.operations[3].meta["dst"], "0")
        self.assertEqual(result.operations[3].meta["length"], "0x18")
        self.assertEqual(result.operations[4].index, "1")

    def test_selected_object_field_edit_uses_active_index_not_size_argument(self) -> None:
        source = '''
def register(sid):
    add(0x80, sid)

def login(sid):
    pass

def logout():
    pass

def exploit():
    register(3)
    login(3)
    edit_bio(0x88, p64(fake_libc_ptr) * 0x11)
    logout()
'''
        result = analyze_heap_source(source)

        self.assertEqual(
            [operation.kind for operation in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.EDIT],
        )
        edit = result.operations[1]
        self.assertEqual(edit.index, "3")
        self.assertEqual(edit.request_size, "0x88")
        self.assertEqual(edit.data, "p64(fake_libc_ptr) * 0x11")
        self.assertEqual(edit.meta.get("parse_confidence"), "active-object-edit")
        self.assertNotIn("unmapped_call", {item.code for item in result.diagnostics})

    def test_default_heap_helpers_are_case_insensitive(self) -> None:
        source = """def Alloc(size):
    pass
def Fill(index, content):
    pass
def Dump(index):
    pass
def Free(index):
    pass
Alloc(0x80)
Fill(0, b'A')
Dump(0)
Free(0)
"""
        result = analyze_heap_source(source)
        self.assertEqual(
            [item.kind for item in result.operations],
            [
                HeapOperationKind.ALLOC,
                HeapOperationKind.EDIT,
                HeapOperationKind.SHOW,
                HeapOperationKind.FREE,
            ],
        )
        self.assertEqual(result.operations[0].request_size, "0x80")

    def test_main_guard_reconnect_loop_inlines_entrypoint_once(self) -> None:
        source = """def add(size, data):
    pass
def delete(index):
    pass
def pwn():
    add(0x30, b'A')
    delete(0)
if __name__ == "__main__":
    while True:
        try:
            pwn()
        except Exception:
            pass
"""
        result = analyze_heap_source(source)
        self.assertEqual(
            [item.kind for item in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.FREE],
        )
        self.assertTrue(any(item.code == "inlined_entrypoint" for item in result.diagnostics))
        self.assertTrue(any(item.code == "bounded_entry_loop" for item in result.diagnostics))

    def test_assert_is_a_runtime_constraint_not_an_unsupported_statement(self) -> None:
        result = analyze_heap_source(
            "target = leak - 0x10\nassert target & 0xf == 0\nadd(0x20, b'A')\n"
        )
        codes = [item.code for item in result.diagnostics]
        self.assertIn("runtime_assertion", codes)
        self.assertNotIn("unsupported_statement", codes)
        self.assertEqual(result.operations[-1].kind, HeapOperationKind.ALLOC)

        stopped = analyze_heap_source("assert 1 == 2\nadd(0x20, b'A')\n")
        self.assertIn("static_assertion_failed", [item.code for item in stopped.diagnostics])
        self.assertEqual(stopped.operations, ())

    def test_multiline_keyword_and_three_alloc_signatures(self) -> None:
        source = """
add(size=0x20, data=b'A')
add(3, 0x40, b'B')
def create(slot, size=0x60, content=b'C'):
    pass
create(7, content=b'D')
def put(data):
    return add(data)
put(b'E')
add(b'F')
add(buf)
"""
        result = analyze_heap_source(source)
        self.assertTrue(result.valid)
        self.assertEqual([(op.index, op.request_size, op.data) for op in result.operations], [
            ("0", "0x20", "b'A'"),
            ("3", "0x40", "b'B'"),
            ("7", "0x60", "b'D'"),
            ("3", "unknown", "b'E'"),
            ("4", "unknown", "b'F'"),
            ("5", "unknown", "buf"),
        ])
        self.assertGreater(result.bindings[0].end_line, result.bindings[0].line - 1)

    def test_alloc_payload_requires_call_or_helper_default_evidence(self) -> None:
        missing = analyze_heap_source("add(0x20)\n")
        self.assertEqual(missing.operations[0].data, "")

        source = """
def add(size, data=b'DEFAULT'):
    pass

add(0x20)
add(0x30, b'EXPLICIT')
"""
        result = analyze_heap_source(source)
        self.assertEqual([operation.data for operation in result.operations], ["b'DEFAULT'", "b'EXPLICIT'"])

    def test_method_alias_wrapper_and_static_star_arguments(self) -> None:
        source = """
def take(idx, size, data):
    return add(idx, size, data)
create = take
args = (2, 0x30, b'X')
heap.create(*args)
release = delete
release(2)
def odd(a, b, c):
    return add(c, b, a)
odd(b'Q', 0x48, 9)
"""
        result = analyze_heap_source(source)
        self.assertEqual([op.kind for op in result.operations], [HeapOperationKind.ALLOC, HeapOperationKind.FREE, HeapOperationKind.ALLOC])
        self.assertEqual(result.operations[0].index, "2")
        self.assertEqual(result.operations[1].chunk, "A")
        self.assertEqual((result.operations[2].index, result.operations[2].request_size, result.operations[2].data), ("9", "0x48", "b'Q'"))

    def test_containers_append_comprehension_enumerate_and_unpack(self) -> None:
        source = """
chunks = []
chunks.append(add(0x20, b'A'))
more = [add(0x30, bytes([i])) for i in range(2)]
for idx, size in enumerate([0x40, 0x50], 3):
    add(idx, size, b'Z')
delete(chunks[0])
delete(more[1])
"""
        result = analyze_heap_source(source)
        self.assertEqual(sum(op.kind == HeapOperationKind.ALLOC for op in result.operations), 5)
        frees = [op for op in result.operations if op.kind == HeapOperationKind.FREE]
        self.assertEqual([op.index for op in frees], ["0", "2"])
        loop_bindings = [binding for binding in result.bindings if binding.loop_env]
        self.assertGreaterEqual(len(loop_bindings), 4)

    def test_unknown_branch_stops_at_common_prefix_until_selected(self) -> None:
        source = "add(0x20,b'A')\nif runtime_flag:\n delete(0)\nelse:\n edit(0,b'B')\nadd(0x30,b'C')\n"
        prefix = analyze_heap_source(source)
        self.assertEqual([op.kind for op in prefix.operations], [HeapOperationKind.ALLOC, HeapOperationKind.NOTE])
        self.assertEqual(prefix.bindings[-1].confidence, "branch_candidate")
        self.assertEqual(len(prefix.branch_groups), 1)
        branch_id = prefix.branch_groups[0].branch_id
        chosen = analyze_heap_source(source, branch_choices={branch_id: "false"})
        self.assertEqual([op.kind for op in chosen.operations], [HeapOperationKind.ALLOC, HeapOperationKind.EDIT, HeapOperationKind.ALLOC])

        dynamic = analyze_heap_source("add(0x20,b'A')\nfor i in runtime_items:\n delete(i)\nadd(0x30,b'B')\n")
        self.assertEqual([op.kind for op in dynamic.operations], [HeapOperationKind.ALLOC, HeapOperationKind.NOTE])
        self.assertEqual(dynamic.bindings[-1].confidence, "unresolved")
        self.assertTrue(any(item.code == "dynamic_iterable" for item in dynamic.diagnostics))

    def test_heap_neutral_debug_guard_keeps_common_suffix(self) -> None:
        source = """
if args.GDB:
    gdb.attach(io)
    pause()
add(0x40, b'A')
delete(0)
"""
        result = analyze_heap_source(source)
        self.assertEqual(
            [item.kind for item in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.FREE],
        )
        self.assertFalse(result.branch_groups)
        self.assertTrue(any(item.code == "heap_neutral_branch" for item in result.diagnostics))

    def test_stateful_login_helpers_loop_indexes_and_recv_only_parser(self) -> None:
        source = """
def reg(sid, name=b'a', password=b'a'):
    menu(1)
    io.sendlineafter(b'ID: ', str(sid).encode())
    io.sendlineafter(b'Name: ', name)
def login(sid):
    menu(2)
def edit_bio(size, data):
    menu(2)
    io.sendline(str(size).encode())
    io.send(data)
def show():
    menu(1)
def leak_bio_qword():
    io.recvuntil(b'Bio: ')
    return u64(io.recv(6).ljust(8, b'\\x00'))
for sid in range(100, 103):
    reg(sid)
login(101)
edit_bio(0x80, b'B')
show()
heap = leak_bio_qword() - 0xbd0
"""
        result = analyze_heap_source(source)
        allocs = [item for item in result.operations if item.kind == HeapOperationKind.ALLOC]
        self.assertEqual([item.index for item in allocs], ["100", "101", "102"])
        self.assertTrue(all(item.request_size == "unknown" for item in allocs))
        edit = next(item for item in result.operations if item.kind == HeapOperationKind.EDIT)
        self.assertEqual((edit.index, edit.request_size, edit.data), ("101", "0x80", "b'B'"))
        shows = [item for item in result.operations if item.kind == HeapOperationKind.SHOW]
        self.assertEqual(len(shows), 1)
        self.assertEqual(shows[0].index, "101")
        derived = result.operations[-1]
        self.assertEqual(derived.kind, HeapOperationKind.DERIVE_VALUE)
        self.assertEqual(derived.meta["source_kind"], "recv")

    def test_dispatch_rule_matches_literal_choice_and_skips_selector(self) -> None:
        rules = [
            {
                "rule_id": "cmd-alloc", "semantic": "alloc",
                "matcher": {"function": "cmd", "arity": 3, "argument_equals": {"0": 1}},
                "output": {"roles": ["size", "index"], "arg_offset": 1}, "enabled": True,
            },
            {
                "rule_id": "cmd-free", "semantic": "free",
                "matcher": {"function": "cmd", "arity": 2, "argument_equals": {"0": 4}},
                "output": {"roles": ["index"], "arg_offset": 1}, "enabled": True,
            },
        ]
        result = analyze_heap_source("cmd(1, 0x100, 7)\ncmd(4, 7)\n", learned_rules=rules)
        self.assertEqual([item.kind for item in result.operations], [HeapOperationKind.ALLOC, HeapOperationKind.FREE])
        self.assertEqual((result.operations[0].index, result.operations[0].request_size), ("7", "0x100"))
        self.assertEqual(result.operations[1].chunk, result.operations[0].chunk)

    def test_complete_variadic_dispatcher_is_inferred_without_manual_rule(self) -> None:
        source = """
def cmd(choice, *values):
    io.sendlineafter(b'choice: ', str(choice).encode())
    for value in values:
        io.sendline(str(value).encode())

cmd(1, 0x100, 7)
cmd(4, 7)
cmd(2, 7, b'payload')
cmd(3, 7)
leak = io.recvn(6)
"""
        result = analyze_heap_source(source)
        self.assertEqual(
            [item.kind for item in result.operations[:4]],
            [HeapOperationKind.ALLOC, HeapOperationKind.FREE, HeapOperationKind.EDIT, HeapOperationKind.SHOW],
        )
        self.assertEqual((result.operations[0].request_size, result.operations[0].index), ("0x100", "7"))
        self.assertTrue(any(item.code == "inferred_dispatcher" for item in result.diagnostics))

    def test_transitive_local_heap_helpers_are_boundedly_inlined(self) -> None:
        source = """
def add(idx, size):
    io.sendline(b'1')
    io.sendline(str(idx).encode())
    io.sendline(str(size).encode())

def delete(idx):
    io.sendline(b'2')
    io.sendline(str(idx).encode())

def setup(base=0):
    for i in range(2):
        add(base + i, 0x20)
    delete(base)

def exploit():
    setup(4)

exploit()
"""
        result = analyze_heap_source(source)
        self.assertEqual(
            [item.kind for item in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.ALLOC, HeapOperationKind.FREE],
        )
        self.assertEqual([item.index for item in result.operations], ["4", "5", "4"])
        self.assertTrue(any(item.code == "inlined_heap_helper" for item in result.diagnostics))

    def test_literal_json_action_calls_map_to_heap_operations(self) -> None:
        source = """
send_json(io, {"op": "capture", "tag": "A", "day": 7, "size": 0x80, "content": b"A"})
send_json(io, {"op": "forget", "tag": "A", "day_from": 7})
out = send_json(io, {"op": "recall", "tag": "A", "day_from": 7})
send_json(io, {"op": "rewrite", "tag": "A", "day": 7, "size": 8, "content": b"B"})
"""
        result = analyze_heap_source(source)
        self.assertEqual(
            [item.kind for item in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.FREE, HeapOperationKind.SHOW, HeapOperationKind.EDIT],
        )
        self.assertEqual((result.operations[0].index, result.operations[0].request_size), ('"A":7', "0x80"))
        self.assertEqual(result.operations[2].meta["result_var"], "out")

    def test_embedded_javascript_object_lifetime_is_visible(self) -> None:
        source = '''
js = r"""
let ledger = new Ledger(48);
let view = ledger.view();
ledger.recycle();
ledger.resize(96);
"""
io.send(js.encode())
'''
        result = analyze_heap_source(source)
        self.assertEqual(
            [item.kind for item in result.operations],
            [HeapOperationKind.ALLOC, HeapOperationKind.SHOW, HeapOperationKind.FREE, HeapOperationKind.EDIT],
        )
        self.assertEqual(result.operations[0].request_size, "48")
        self.assertTrue(any(item.code == "embedded_heap_script" for item in result.diagnostics))

    def test_attribute_assignment_keeps_recv_derive_value(self) -> None:
        result = analyze_heap_source(
            "show(0)\nlibc.address = u64(io.recvn(6).ljust(8, b'\\x00')) - 0x1234\n"
        )
        self.assertEqual([item.kind for item in result.operations], [HeapOperationKind.SHOW, HeapOperationKind.DERIVE_VALUE])
        self.assertEqual(result.operations[1].chunk, "libc.address")

    def test_show_recv_unpack_provenance(self) -> None:
        source = """
show(7)
data = io.recvline().strip()
heap = u64(data[:5].ljust(8, b'\\x00')) << 12
other = int.from_bytes(data[:4], 'little') + 0x10
"""
        result = analyze_heap_source(source)
        self.assertEqual([op.kind for op in result.operations], [
            HeapOperationKind.SHOW,
            HeapOperationKind.DERIVE_VALUE,
            HeapOperationKind.DERIVE_VALUE,
            HeapOperationKind.DERIVE_VALUE,
        ])
        heap = result.operations[2]
        self.assertEqual(heap.meta["byte_width"], "8")
        self.assertEqual(heap.meta["endian"], "little")
        self.assertEqual(heap.meta["observed_bytes"], "5")
        self.assertIn("data", heap.meta["dependencies"])

    def test_nested_show_precedes_outer_derive(self) -> None:
        result = analyze_heap_source("old_fd = u64(show(15)[:8].ljust(8, b'\\x00'))\n")
        self.assertEqual(
            [operation.kind for operation in result.operations],
            [HeapOperationKind.SHOW, HeapOperationKind.DERIVE_VALUE],
        )
        self.assertEqual(result.operations[0].meta["result_var"], "old_fd_raw")
        self.assertIn("old_fd_raw", result.operations[1].value)

    def test_fake_chunk_flat_and_p64_builder(self) -> None:
        source = """
fake = p64(0)
fake += p64(0x91)
fake += p64(fd)
fake += p64(bk)
second = flat(0, 0x71, target ^ (pos >> 12), 0)
"""
        result = analyze_heap_source(source)
        fake = [op for op in result.operations if op.kind == HeapOperationKind.FAKE_CHUNK]
        # v0.10 records structure-compatible layouts as candidates without
        # claiming allocator confirmation; variable naming is not evidence.
        self.assertEqual(len(fake), 2)
        self.assertEqual(fake[0].meta["size"], "0x91")
        self.assertEqual(fake[0].chunk, "fake")
        self.assertTrue(all(item.meta["evidence_level"] == "candidate" for item in fake))

    def test_packed_rop_chain_is_not_a_fake_chunk(self) -> None:
        source = "payload = p64(0) + flat(ret, pop_rdi, bin_sh, pop_rsi, 0, system)\n"
        result = analyze_heap_source(source)
        self.assertFalse(any(op.kind == HeapOperationKind.FAKE_CHUNK for op in result.operations))

    def test_never_executes_user_calls_and_bounds_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "executed"
            source = f"__import__('pathlib').Path({str(marker)!r}).write_text('bad')\nfor i in range(999):\n add(0x20,i)\n"
            result = analyze_heap_source(source, max_loop_iterations=8, max_events=5)
            self.assertFalse(marker.exists())
            self.assertEqual(len(result.operations), 5)
            self.assertTrue(any(item.code in {"loop_truncated", "events_truncated"} for item in result.diagnostics))

    def test_syntax_error_is_invalid_without_guessing(self) -> None:
        result = analyze_heap_source("add(0x20, b'A'\ndelete(0)\n")
        self.assertFalse(result.valid)
        self.assertEqual(result.operations, ())
        self.assertEqual(result.diagnostics[0].code, "syntax_error")

    def test_override_rebind_and_stale_detection(self) -> None:
        source = "add(0x20,b'A')\ndelete(0)\n"
        first = analyze_heap_source(source)
        binding = first.bindings[1]
        replacement = HeapOperation("", HeapOperationKind.SHOW, index="0")
        override = TimelineOverride("fix1", binding.source_id, "replace", replacement, True, binding.source_text, binding.fingerprint)
        changed = analyze_heap_source(source, overrides=[override])
        self.assertEqual(changed.operations[1].kind, HeapOperationKind.SHOW)
        stale = analyze_heap_source("add(0x20,b'A')\n", overrides=[override])
        self.assertTrue(any(item.code == "stale_override" for item in stale.diagnostics))

    def test_signature_rule_does_not_cross_apply_to_unrelated_positional_add(self) -> None:
        rule = {
            "rule_id": "add-size-index",
            "semantic": "alloc",
            "matcher": {
                "function": "add",
                "arity": 2,
                "keywords": [],
                "parameter_names": ["size", "idx"],
            },
            "output": {"roles": ["size", "index"]},
            "enabled": True,
        }
        unrelated = analyze_heap_source("add(0x20, b'A')\n", learned_rules=[rule])
        self.assertEqual((unrelated.operations[0].index, unrelated.operations[0].data), ("0", "b'A'"))

        exact = analyze_heap_source(
            "def add(size, idx):\n    pass\nadd(0x20, 7)\n",
            learned_rules=[rule],
        )
        self.assertEqual((exact.operations[0].index, exact.operations[0].request_size), ("7", "0x20"))
        self.assertEqual(exact.operations[0].meta["learned_rule_id"], "add-size-index")

    def test_memory_regions_distinguish_unknown_zero_and_known(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        unknown = GlibcHeapEngine(config).replay([
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'TAKE'"),
        ])[-1].chunks["A"]
        self.assertTrue(any(region.state == "known" for region in unknown.memory_regions))
        self.assertTrue(any(region.state == "unknown" for region in unknown.memory_regions))
        self.assertFalse(any(region.state == "zero" for region in unknown.memory_regions))

        zeroed = GlibcHeapEngine(config).replay([
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'\\x00' * 0x60"),
        ])[-1].chunks["A"]
        zero_regions = [region for region in zeroed.memory_regions if region.state == "zero"]
        self.assertEqual(len(zero_regions), 1)
        self.assertEqual((zero_regions[0].start, zero_regions[0].end), (0x10, 0x70))

    def test_scenario_v1_compatibility_and_v4_analysis_state(self) -> None:
        legacy = HeapScenario.from_dict({"schema_version": 1, "operations": []})
        self.assertEqual(legacy.timeline_overrides, [])
        scenario = HeapScenario(
            behavior_profile=ChallengeBehaviorProfile(
                name="student challenge",
                helpers=(
                    ChallengeCallBehavior(
                        "reg",
                        ("sid",),
                        (BehaviorEffect("alloc", "student[{sid}]", "{sid}", "0x88"),),
                    ),
                ),
            ),
            branch_choices={"branch": "true"},
            helper_mappings=[{"semantic": "alloc", "function": "take"}],
            ai_review_ids=["fb1"],
            ai_instruction="take 是 alloc",
            disabled_global_rule_ids=["rule2"],
            ai_scene_rules=[{
                "rule_id": "scene1",
                "semantic": "alloc",
                "matcher": {"function": "take", "arity": 3},
                "output": {"roles": ["index", "size", "data"]},
            }],
            ai_memory_annotations=[{
                "step": 1,
                "chunk": "A",
                "start": 0x10,
                "end": 0x18,
                "state": "known",
                "provenance": "inferred",
            }],
        )
        restored = HeapScenario.from_dict(scenario.to_dict())
        self.assertEqual(restored.schema_version, 5)
        self.assertEqual(restored.behavior_profile.name, "student challenge")
        self.assertEqual(restored.behavior_profile.helpers[0].effects[0].chunk, "student[{sid}]")
        self.assertEqual(restored.branch_choices["branch"], "true")
        self.assertEqual(restored.helper_mappings[0]["function"], "take")
        self.assertEqual(restored.ai_review_ids, ["fb1"])
        self.assertEqual(restored.ai_instruction, "take 是 alloc")
        self.assertEqual(restored.disabled_global_rule_ids, ["rule2"])
        self.assertEqual(restored.ai_scene_rules[0]["matcher"]["function"], "take")
        self.assertEqual(restored.ai_memory_annotations[0]["provenance"], "inferred")


if __name__ == "__main__":
    unittest.main()
