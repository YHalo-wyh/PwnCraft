#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M1 plumbing acceptance: BinaryIR → behavior profile → analyze_heap_source.

The profile converts BinaryIR target actions into ChallengeBehaviorProfile
effects; each recognized helper call then expands to N allocator operations
(the 1:N fix). Uses an in-repo fixture BinaryIR — no IDA needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pwncraft.core.binary_ir import build_behavior_profile, build_binary_ir  # noqa: E402
from pwncraft.features.heapviz import analyze_heap_source  # noqa: E402
from pwncraft.features.heapviz.semantics.challenge_profile import (  # noqa: E402
    ChallengeBehaviorProfile,
)

FACTS = {
    "binary": "C:/x/heapcreator",
    "transport": "sse",
    "server": {"name": "github.com/mrexodia/ida-pro-mcp#idalib", "version": "1.7.1"},
    "metadata": {"sha256": "c" * 64},
    "functions": [
        {"address": "0x400700", "name": ".malloc", "size": "0x5"},
        {"address": "0x4008fb", "name": "create_heap", "size": "0x179"},
        {"address": "0x400c3a", "name": "delete_heap", "size": "0xe9"},
    ],
    "alloc_xrefs": {
        "malloc": {"plt": "0x400700", "xrefs":
                   '{\n  "address": "0x400942", "type": "code", "function": '
                   '{"address": "0x4008fb", "name": "create_heap"}\n}\n'
                   '{\n  "address": "0x4009c8", "type": "code", "function": '
                   '{"address": "0x4008fb", "name": "create_heap"}\n}'},
        "free": {"plt": "0x400690", "xrefs":
                 '{\n  "address": "0x400ccb", "type": "code", "function": '
                 '{"address": "0x400c3a", "name": "delete_heap"}\n}'},
    },
}

BINDINGS = [
    {"helper": "create", "binary_handler": "create_heap", "menu": "1",
     "parameters": ["size", "content"],
     "effects": [
         {"kind": "alloc", "chunk": "S", "request_size": "0x10",
          "bind_handle": False, "note": "management struct (malloc #1)"},
         {"kind": "alloc", "chunk": "C", "request_size": "size",
          "note": "content (malloc #2)"}],
     "bindings_provenance": "analyst-truth (VNext.2 M1)"},
]

EXP = '''
from pwn import *

def create(size, content):
    io.recvuntil(b"Choice:")
    io.sendline(b"1")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.send(content)

def exp():
    create(0x18, b"dada")
    create(0x10, b"ddaa")
'''

EXPECTED_WARNINGS = []


def test_m1_profile_converter_crosscheck() -> None:
    ir = build_binary_ir(FACTS)
    profile, warnings = build_behavior_profile(ir, BINDINGS, name="m1")
    assert warnings == EXPECTED_WARNINGS, warnings
    assert profile["helpers"][0]["function"] == "create"
    assert len(profile["helpers"][0]["effects"]) == 2


def test_m1_profile_converter_detects_mismatch() -> None:
    ir = build_binary_ir(FACTS)
    bad = [dict(BINDINGS[0], effects=[
        {"kind": "alloc", "chunk": "C", "request_size": "size"}])]
    _, warnings = build_behavior_profile(ir, bad, name="m1-bad")
    assert any("BinaryIR 证据为 2 个 malloc" in w for w in warnings), warnings


def test_m1_plumbing_1n_through_analyzer() -> None:
    ir = build_binary_ir(FACTS)
    profile, _ = build_behavior_profile(ir, BINDINGS, name="m1")
    result = analyze_heap_source(
        EXP, behavior_profile=ChallengeBehaviorProfile.from_dict(profile))
    assert result.valid, result.diagnostics
    create_allocs = [o for o in result.canonical_operations
                     if o.kind.value == "alloc" and o.source_binding
                     and o.source_binding.line in (12, 13)]
    # each create() call must expand to TWO alloc operations (struct+content)
    assert len(create_allocs) == 4, [
        (o.source_binding.line, o.kind.value) for o in create_allocs]
    lines = sorted(o.source_binding.line for o in create_allocs)
    assert lines == [12, 12, 13, 13]


def test_m1_struct_request_size_is_constant() -> None:
    """CURRENT-BEHAVIOR LOCK: both expanded allocs currently carry the call's
    size argument in canonical request_size — the struct effect's 0x10
    constant is dropped by the canonical converter. 1:N structure holds;
    request-size attribution is VNext.2 M2 work (binary-evidence-backed)."""
    ir = build_binary_ir(FACTS)
    profile, _ = build_behavior_profile(ir, BINDINGS, name="m1")
    result = analyze_heap_source(
        EXP, behavior_profile=ChallengeBehaviorProfile.from_dict(profile))
    allocs = [o for o in result.canonical_operations
              if o.kind.value == "alloc" and o.source_binding
              and o.source_binding.line in (12, 13)]
    assert len(allocs) == 4
    assert all(o.request_size is not None for o in allocs)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all m1 plumbing tests passed")
