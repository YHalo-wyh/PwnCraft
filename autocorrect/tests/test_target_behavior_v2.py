#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pwncraft"))

import target_behavior_v2 as T  # noqa: E402


def _op(op_id: str, kind: str, line: int, call: str, *, request=None, handle=None):
    return {
        "op_id": op_id,
        "kind": kind,
        "source_line": line,
        "source_call": call,
        "allocator_request": request or {"kind": "unknown", "reason": "n/a"},
        "handle": handle or {"kind": "unknown", "reason": "n/a"},
    }


def _write_bindings(tmp_path: Path, bindings: list[dict]) -> Path:
    path = tmp_path / "behavior_bindings.json"
    path.write_text(json.dumps({"bindings": bindings}), encoding="utf-8")
    return path


def test_create_lowers_one_canonical_call_to_two_mallocs(tmp_path: Path) -> None:
    path = _write_bindings(tmp_path, [{
        "helper": "create",
        "binary_handler": "create_heap",
        "parameters": ["size", "content"],
        "effects": [
            {"kind": "alloc", "request_size": "0x10", "role": "management_struct"},
            {"kind": "alloc", "request_size": "size", "role": "content"},
        ],
        "bindings_provenance": "binary/source reviewed",
    }])
    bindings = T.load_bindings(path)
    target = T.derive_target_behavior([
        _op("op1", "alloc", 44, "create(0x18, 'dada')")
    ], bindings)
    entry = target["per_op"][0]
    assert entry["internals_not_modeled"] is False
    assert [item["action"] for item in entry["actions"]] == ["malloc", "malloc"]
    assert [item["request"]["value"] for item in entry["actions"]] == [0x10, 0x18]
    assert [item.get("role") for item in entry["actions"]] == ["management_struct", "content"]


def test_delete_lowers_to_two_distinct_free_actions(tmp_path: Path) -> None:
    path = _write_bindings(tmp_path, [{
        "helper": "delete",
        "binary_handler": "delete_heap",
        "parameters": ["idx"],
        "effects": [
            {"kind": "free", "index": "idx", "role": "content"},
            {"kind": "free", "index": "idx", "role": "management_struct"},
        ],
    }])
    target = T.derive_target_behavior([
        _op("op2", "delete", 50, "delete(1)", handle={"kind": "concrete", "value": 1})
    ], T.load_bindings(path))
    actions = target["per_op"][0]["actions"]
    assert [item["action"] for item in actions] == ["free", "free"]
    assert [item["target"]["value"] for item in actions] == [1, 1]
    assert [item.get("role") for item in actions] == ["content", "management_struct"]


def test_unbound_call_keeps_identity_fallback() -> None:
    request = {"kind": "concrete", "value": 0x80, "source": "0x80"}
    target = T.derive_target_behavior([
        _op("op3", "alloc", 10, "allocate(0x80)", request=request)
    ])
    entry = target["per_op"][0]
    assert entry["internals_not_modeled"] is True
    assert entry["actions"] == [{
        "action": "malloc",
        "request": request,
        "source": "canonical_identity_fallback",
    }]


def test_legacy_helper_key_is_normalized_but_malformed_binding_is_rejected(tmp_path: Path) -> None:
    good = _write_bindings(tmp_path, [{
        "helper": "show",
        "parameters": ["idx"],
        "effects": [{"kind": "show", "index": "idx"}],
    }])
    assert T.load_bindings(good)[0]["function"] == "show"

    bad = _write_bindings(tmp_path, [{
        "parameters": ["idx"],
        "effects": [{"kind": "free", "index": "idx"}],
    }])
    try:
        T.load_bindings(bad)
    except ValueError as error:
        assert "helper/function" in str(error)
    else:
        raise AssertionError("malformed behavior binding must not be silently ignored")


def test_keyword_arguments_are_bound_without_execution(tmp_path: Path) -> None:
    path = _write_bindings(tmp_path, [{
        "helper": "create",
        "parameters": ["size", "content"],
        "effects": [{"kind": "alloc", "request_size": "size"}],
    }])
    target = T.derive_target_behavior([
        _op("op4", "alloc", 12, "create(content=b'A', size=0x30)")
    ], T.load_bindings(path))
    request = target["per_op"][0]["actions"][0]["request"]
    assert request["kind"] == "concrete"
    assert request["value"] == 0x30
