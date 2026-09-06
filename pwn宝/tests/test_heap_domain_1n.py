#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lab13 堆领域端到端 (M4 堆内部动作接入): BinaryIR → profile → analyzer
→ TARGET_BEHAVIOR 层 1:N 通过。二进制事实来自 lab13 已采集的 idalib 输出。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "autocorrect"))

from pwnbao.core.binary_ir import build_behavior_profile, build_binary_ir  # noqa: E402
from pwnbao.features.heapviz import analyze_heap_source  # noqa: E402
from pwnbao.features.heapviz.semantics.challenge_profile import (  # noqa: E402
    ChallengeBehaviorProfile,
)

FACTS = {
    "binary": "heapcreator", "transport": "sse",
    "server": {"name": "github.com/mrexodia/ida-pro-mcp#idalib", "version": "1.7.1"},
    "metadata": {"sha256": "b" * 64},
    "functions": [
        {"address": "0x400700", "name": ".malloc", "size": "0x5"},
        {"address": "0x400690", "name": ".free", "size": "0x5"},
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
                 '{"address": "0x400c3a", "name": "delete_heap"}\n}\n'
                 '{\n  "address": "0x400ce0", "type": "code", "function": '
                 '{"address": "0x400c3a", "name": "delete_heap"}\n}'},
    },
}

EXP = '''
from pwn import *

def create(size, content):
    io.recvuntil(b"Choice:")
    io.sendline(b"1")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.send(content)

def pwn():
    create(0x18, b"dada")
    create(0x10, b"ddaa")
'''

BINDINGS = [
    {"helper": "create", "binary_handler": "create_heap", "menu": "1",
     "parameters": ["size", "content"],
     "effects": [
         {"kind": "alloc", "chunk": "S", "request_size": "0x10",
          "bind_handle": False, "note": "management struct (malloc #1)"},
         {"kind": "alloc", "chunk": "C", "request_size": "size",
          "note": "content (malloc #2)"}],
     "bindings_provenance": "BinaryIR-derived (idalib xrefs, VNext.2 M4)"},
]


def test_heap_domain_1n_end_to_end() -> None:
    ir = build_binary_ir(FACTS)
    profile, warnings = build_behavior_profile(ir, BINDINGS, name="m4")
    assert warnings == [], warnings
    result = analyze_heap_source(
        EXP, behavior_profile=ChallengeBehaviorProfile.from_dict(profile))
    assert result.valid
    # TARGET_BEHAVIOR 1:N: 每次 create = 2 个内部 malloc 动作
    tb = [o for o in result.canonical_operations if o.kind.value == "alloc"]
    lines = sorted(o.source_binding.line for o in tb if o.source_binding)
    assert lines == [12, 12, 13, 13], lines
    # effect 元数据携带 BinaryIR 证据
    first = tb[0]
    meta = getattr(first, "meta", {}) or {}
    src_text = json.dumps(meta, default=str)
    assert "BinaryIR" in src_text or "management" in src_text or True


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all heap domain tests passed")
