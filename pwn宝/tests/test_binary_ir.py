"""BinaryIR extraction tests (VNext.1) — deterministic, no IDA needed.

Fixture mirrors real ida-pro-mcp#idalib v1.7.1 output shapes captured from
the lab13 acceptance run (get_xrefs_to returns SEVERAL consecutive JSON
objects as one text payload; PLT functions appear both as .name and name).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pwnbao.core.binary_ir import (  # noqa: E402
    BEHAVIOR_LABELS,
    BinaryIR,
    build_binary_ir,
)

FACTS = {
    "binary": "C:/x/heapcreator",
    "transport": "sse",
    "server": {"name": "github.com/mrexodia/ida-pro-mcp#idalib", "version": "1.7.1"},
    "metadata": {"sha256": "b" * 64},
    "degrade_notes": ["main: decompile unavailable -> disassembly (Qt)"],
    "functions": [
        {"address": "0x400658", "name": ".init_proc", "size": "0x1a"},
        {"address": "0x400700", "name": ".malloc", "size": "0x5"},
        {"address": "0x400690", "name": ".free", "size": "0x5"},
        {"address": "0x4008fb", "name": "create_heap", "size": "0x179"},
        {"address": "0x400c3a", "name": "delete_heap", "size": "0xe9"},
        {"address": "0x400d40", "name": "show_heap", "size": "0x60"},
        {"address": "0x401000", "name": "menu", "size": "0x40"},
        {"address": "0x401100", "name": "main", "size": "0x80"},
        {"address": "0x400700", "name": "malloc", "size": "0x5"},
        {"address": "0x400690", "name": "free", "size": "0x5"},
    ],
    "alloc_xrefs": {
        # v1.7 shape: SEVERAL consecutive JSON objects in one text payload
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
        "calloc": "<not present>",
        "realloc": {"plt": "", "xrefs": "not json at all"},
    },
}


def test_t1_consecutive_json_objects_parse() -> None:
    ir = build_binary_ir(FACTS)
    kinds = [(e.callee, e.caller) for e in ir.allocator_callsites]
    assert kinds == [("malloc", "create_heap"), ("malloc", "create_heap"),
                     ("free", "delete_heap"), ("free", "delete_heap")]
    assert ir.allocator_callsites[0].evidence_id == 1


def test_t2_target_actions_expose_1n() -> None:
    ir = build_binary_ir(FACTS)
    create = ir.target_actions["create_heap"]
    free_h = ir.target_actions["delete_heap"]
    assert [a["action"] for a in create["actions"]] == ["malloc", "malloc"]
    assert [a["action"] for a in free_h["actions"]] == ["free", "free"]
    # request_argument is instruction-level evidence (VNext.2): explicit unknown
    assert all(a["request_argument"] is None for a in create["actions"])


def test_t3_plt_and_libc_stubs_not_menu_handlers() -> None:
    ir = build_binary_ir(FACTS)
    handlers = ir.menu_handlers
    assert handlers == {"alloc": "create_heap", "free": "delete_heap",
                        "show": "show_heap"}
    names = [f.name for f in ir.functions]
    assert "malloc" not in names and ".free" not in names


def test_t4_provenance_and_unknowns() -> None:
    ir = build_binary_ir(FACTS)
    assert ir.provenance["engine_version"] == "1.7.1"
    assert ir.provenance["degraded"] is True
    assert any("calloc" in u for u in ir.unknowns)
    assert any("realloc" in u for u in ir.unknowns)


def test_t5_roundtrip_and_labels() -> None:
    ir: BinaryIR = build_binary_ir(FACTS)
    payload = ir.to_dict()
    assert payload["schema_version"] == "1.0"
    assert payload["binary_sha256"] == "b" * 64
    # behavior vocabulary is defined and machine-consumable
    assert "CLEAR_POINTER" in BEHAVIOR_LABELS
    # owner amendment: observational labels only — NO_INDEX_CHECK is banned
    assert "INDEX_CHECK_NOT_OBSERVED" in BEHAVIOR_LABELS
    assert "NO_INDEX_CHECK" not in BEHAVIOR_LABELS


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all binary_ir tests passed")
