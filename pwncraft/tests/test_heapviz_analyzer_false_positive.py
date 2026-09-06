from __future__ import annotations

import unittest

from pwncraft.features.heapviz import (
    BehaviorEffect,
    ChallengeBehaviorProfile,
    ChallengeCallBehavior,
    GlibcHeapEngine,
    HeapOperationKind,
    analyze_heap_source,
    build_allocator_config,
)


class HeapAnalyzerFalsePositiveTests(unittest.TestCase):
    def test_magic_numbers_shellcode_exp_stays_heap_neutral(self) -> None:
        """Real contest EXP: transformed shellcode transport is not a heap API."""
        source = """
from pwn import *
context.arch = 'i386'

def start():
    return process(['./libc/ld-linux.so.2', '--library-path', './libc', './pwn'])

SC = bytes.fromhex('89cc31c05068666c6167')
assert b'\\x00' not in SC
payload = SC.ljust(0x280, b'\\x90')
assert len(payload) == 0x280 and b'\\x00' not in payload
io = start()
for i in range(1, 5):
    io.sendlineafter(f'MAGIC {i}: '.encode(), b'0')
io.sendafter(b'WHAT CAT I SAY: ', payload)
io.interactive()
"""
        result = analyze_heap_source(source)

        self.assertTrue(result.valid)
        self.assertEqual(result.operations, ())
        self.assertEqual(
            [event.target.qualified_name for event in result.program_events],
            [
                "bytes.fromhex",
                "SC.ljust",
                "start",
                "io.sendlineafter",
                "io.sendlineafter",
                "io.sendlineafter",
                "io.sendlineafter",
                "io.sendafter",
                "io.interactive",
            ],
        )
        self.assertEqual(
            [item.code for item in result.diagnostics],
            ["runtime_assertion", "runtime_assertion"],
        )

    def test_python_container_and_path_methods_never_create_heap_events(self) -> None:
        source = """
config = {}
items = [1, 2]
config.update({"x": 1})
items.remove(1)
x = set([1, 2, 3])
path.move(1, 2, 3)
os.remove("fixture")
shutil.copy("a", "b")
widget.delete(7)
cache.update({"y": 2})
"""
        result = analyze_heap_source(source)

        self.assertEqual(result.operations, ())
        self.assertNotIn("unmapped_call", {item.code for item in result.diagnostics})
        targets = {item.target.qualified_name: item.target.origin for item in result.program_events}
        self.assertEqual(targets["config.update"], "python_builtin")
        self.assertEqual(targets["items.remove"], "python_builtin")
        self.assertEqual(targets["set"], "python_builtin")
        self.assertEqual(targets["path.move"], "python_builtin")
        self.assertEqual(targets["os.remove"], "python_builtin")
        self.assertEqual(targets["shutil.copy"], "python_builtin")
        self.assertEqual(targets["widget.delete"], "heuristic")
        self.assertEqual(targets["cache.update"], "heuristic")

    def test_defined_ambiguous_helpers_and_challenge_receivers_still_work(self) -> None:
        source = """
def update(idx, content):
    pass

update(0, b'A')
heap.create(1, 0x30, b'B')
client.delete(1)
"""
        result = analyze_heap_source(source)

        self.assertEqual(
            [item.kind for item in result.operations],
            [HeapOperationKind.EDIT, HeapOperationKind.ALLOC, HeapOperationKind.FREE],
        )
        origins = [event.target.origin for event in result.program_events if event.target.function_name in {"update", "create", "delete"}]
        self.assertEqual(origins, ["user_helper", "challenge_receiver", "challenge_receiver"])

    def test_challenge_behavior_expands_one_helper_into_multiple_mallocs(self) -> None:
        profile = ChallengeBehaviorProfile(
            name="student challenge",
            helpers=(
                ChallengeCallBehavior(
                    "reg",
                    ("sid", "name", "password"),
                    (
                        BehaviorEffect("alloc", "student[{sid}]", "{sid}", "0x88", bind_handle=True),
                        BehaviorEffect("alloc", "student[{sid}].name", request_size="len(name) + 1", data="{name}", bind_handle=False),
                        BehaviorEffect("alloc", "student[{sid}].password", request_size="len(password) + 1", data="{password}", bind_handle=False),
                    ),
                    evidence="reversed register_student() body",
                ),
            ),
        )
        result = analyze_heap_source(
            "reg(3, b'wyh', b'123456')\n",
            behavior_profile=profile,
        )

        self.assertEqual([item.chunk for item in result.operations], [
            "student[3]", "student[3].name", "student[3].password",
        ])
        self.assertEqual([item.request_size for item in result.operations], ["0x88", "0x4", "0x7"])
        self.assertEqual(result.operations[1].data, "b'wyh'")
        self.assertEqual(result.operations[1].meta["bind_handle"], "false")
        snapshots = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35")).replay(result.operations)
        final = snapshots[-1]
        self.assertEqual(final.handles["3"].chunk_id, "student[3]")
        self.assertEqual(len(final.chunks), 3)
        self.assertTrue(all(item.meta.get("evidence") for item in result.operations))

    def test_program_ir_keeps_safe_linking_expression_structure(self) -> None:
        result = analyze_heap_source("edit(0, p64(target ^ (pos >> 12)))\n")
        event = next(item for item in result.program_events if item.target.function_name == "edit")
        packed = event.args[1]
        self.assertEqual(packed.kind, "byte_concat")
        self.assertEqual(packed.children[0].kind, "xor")
        self.assertEqual(packed.children[0].children[1].kind, "shift_right")

    def test_behavior_profile_rejects_silent_schema_downgrades(self) -> None:
        with self.assertRaisesRegex(ValueError, "未知 behavior effect kind"):
            ChallengeBehaviorProfile.from_dict({
                "helpers": [{
                    "function": "reg",
                    "parameters": ["idx"],
                    "effects": [{"kind": "teleport_chunk", "index": "{idx}"}],
                }],
            })

        with self.assertRaisesRegex(ValueError, "helper.function"):
            ChallengeBehaviorProfile.from_dict({
                "helpers": [{"function": "", "parameters": [], "effects": []}],
            })

        with self.assertRaisesRegex(TypeError, "helpers.*JSON array"):
            ChallengeBehaviorProfile.from_dict({"helpers": {"function": "reg"}})
        with self.assertRaisesRegex(TypeError, "behavior profile.*JSON object"):
            ChallengeBehaviorProfile.from_dict([])

    def test_challenge_profile_evidence_wins_over_conflicting_learned_rule(self) -> None:
        profile = ChallengeBehaviorProfile(
            name="ground truth",
            helpers=(
                ChallengeCallBehavior(
                    "reg",
                    ("idx",),
                    (BehaviorEffect("alloc", "student[{idx}]", "{idx}", "0x88"),),
                    evidence="reversed challenge body",
                ),
            ),
        )
        conflicting_rule = {
            "rule_id": "stale-reg-rule",
            "semantic": "free",
            "matcher": {"function": "reg", "arity": 1},
            "output": {"roles": ["index"]},
            "enabled": True,
        }
        result = analyze_heap_source(
            "reg(3)\n",
            behavior_profile=profile,
            learned_rules=[conflicting_rule],
        )

        self.assertEqual([item.kind for item in result.operations], [HeapOperationKind.ALLOC])
        event = next(item for item in result.program_events if item.target.function_name == "reg")
        self.assertEqual(event.kind, "call")
        self.assertEqual(event.target.origin, "profile")
        self.assertEqual(event.evidence[0].kind, "challenge_profile")


if __name__ == "__main__":
    unittest.main()
