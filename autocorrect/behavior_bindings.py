#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""behavior_bindings: analyst-truth 派生的 behavior profile 绑定。

每个 case 的绑定从 expected_truth.json 的 target_behavior 层派生（analyst
已锁定的事实），用于构造 ChallengeBehaviorProfile 注入 run_case 管线。
这些绑定是「消费者」（消费 BinaryIR/expected truth 的既有结论），不引入新推断。
"""
from __future__ import annotations

LAB13_BINDINGS = [
    {"helper": "create", "binary_handler": "create_heap", "menu": "1",
     "parameters": ["size", "content"],
     "effects": [
         {"kind": "alloc", "chunk": "S", "request_size": "0x10",
          "bind_handle": False, "note": "management struct (malloc #1)"},
         {"kind": "alloc", "chunk": "C", "request_size": "size",
          "note": "content (malloc #2)"}],
     "bindings_provenance": "analyst-truth (heapcreator.c L40+L48, VNext.2 M2)"},
    {"helper": "edit", "binary_handler": "edit_heap", "menu": "2",
     "parameters": ["idx", "size", "content"],
     "effects": [{"kind": "edit", "index": "idx", "data": "content",
                  "note": "read_input(content, size+1)"}],
     "bindings_provenance": "analyst-truth (heapcreator.c L74)"},
    {"helper": "free", "binary_handler": "delete_heap", "menu": "4",
     "parameters": ["idx"],
     "effects": [{"kind": "free", "index": "idx"}],
     "bindings_provenance": "analyst-truth (heapcreator.c L111-113, two free calls)"},
    {"helper": "dump", "binary_handler": "show_heap", "menu": "3",
     "parameters": ["idx"],
     "effects": [{"kind": "show", "index": "idx",
                  "note": "printf Size/Content"}],
     "bindings_provenance": "analyst-truth (heapcreator.c L92)"},
]

NOTE2_BINDINGS = [
    {"helper": "newnote", "binary_handler": "newnote", "menu": "1",
     "parameters": ["length", "content"],
     "effects": [{"kind": "alloc", "chunk": "C", "request_size": "length",
                  "note": "malloc(length) + read content"}],
     "bindings_provenance": "analyst-truth (exp.py prompt dataflow)"},
    {"helper": "shownote", "binary_handler": "shownote", "menu": "2",
     "parameters": ["id"],
     "effects": [{"kind": "show", "index": "id",
                  "note": "recvuntil + is: output"}],
     "bindings_provenance": "analyst-truth (exp.py callsite OUTPUT_DATA_FLOW)"},
    {"helper": "editnote", "binary_handler": "editnote", "menu": "3",
     "parameters": ["id", "choice", "content"],
     "effects": [{"kind": "edit", "index": "id", "data": "content",
                  "note": "choice submenu + write content"}],
     "bindings_provenance": "analyst-truth (CALLSITE_ARGUMENT_BINDING, exp.py:27-33)"},
    {"helper": "deletenote", "binary_handler": "deletenote", "menu": "4",
     "parameters": ["id"],
     "effects": [{"kind": "free", "index": "id",
                  "note": "free note"}],
     "bindings_provenance": "analyst-truth (exp.py callsite)"},
]

BINDINGS_BY_CASE = {
    "heap-ctf-wiki-hitcontraning-lab13-bae716d5": LAB13_BINDINGS,
    "heap-ctf-wiki-2016-zctf-note2-a85b75f2": NOTE2_BINDINGS,
}
