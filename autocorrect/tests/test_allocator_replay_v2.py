#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pwncraft"))

import allocator_replay_v2 as A  # noqa: E402
from pwncraft.features.heapviz.engine import GlibcHeapEngine  # noqa: E402
from pwncraft.features.heapviz.models import AllocatorConfig  # noqa: E402
from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind  # noqa: E402


def _alloc(op_id: str, size: str, data: str = "b'A'") -> HeapOperation:
    return HeapOperation(op_id, HeapOperationKind.ALLOC, request_size=size, data=data)


def _free(op_id: str, index: str) -> HeapOperation:
    return HeapOperation(op_id, HeapOperationKind.FREE, index=index)


def _create_entry(op_id: str, content_size: int) -> dict:
    return {
        "op_id": op_id,
        "kind": "alloc",
        "internals_not_modeled": False,
        "handle_policy": {"kind": "lowest_free_index", "limit": 4},
        "actions": [
            {"action": "malloc", "request": {"kind": "concrete", "value": 0x10},
             "role": "management_struct", "bind_handle": False},
            {"action": "malloc", "request": {"kind": "concrete", "value": content_size},
             "role": "content", "bind_handle": True},
        ],
    }


def _delete_entry(op_id: str, index: int) -> dict:
    return {
        "op_id": op_id,
        "kind": "delete",
        "internals_not_modeled": False,
        "actions": [
            {"action": "free", "target": {"kind": "concrete", "value": index},
             "role": "content"},
            {"action": "free", "target": {"kind": "concrete", "value": index},
             "role": "management_struct"},
        ],
    }


def _config() -> AllocatorConfig:
    return AllocatorConfig(
        version=(2, 23),
        tcache_enabled=False,
        safe_linking=False,
        tcache_key_check=False,
    )


def test_grouped_replay_keeps_one_parent_step_with_two_allocator_events() -> None:
    parents = (
        _alloc("op_001", "0x18", "b'dada'"),
        _alloc("op_002", "0x10", "b'ddaa'"),
        _free("op_003", "1"),
    )
    target = {"per_op": [
        _create_entry("op_001", 0x18),
        _create_entry("op_002", 0x10),
        _delete_entry("op_003", 1),
    ]}
    plan = A.build_replay_plan(parents, target)
    assert plan.expanded_parent_count == 3
    assert [group.handle for group in plan.groups] == ["0", "1", "1"]
    assert len(plan.operations) == 6

    expanded = GlibcHeapEngine(_config()).replay(plan.operations)
    collapsed = A.collapse_snapshots(expanded, plan)
    assert len(collapsed) == 4  # initial + three canonical parent steps
    assert [snapshot.operation_id for snapshot in collapsed] == [
        "initial", "op_001", "op_002", "op_003"
    ]
    assert len(collapsed[1].alloc_events) == 2
    assert [event.request_size for event in collapsed[1].alloc_events] == ["0x10", "0x18"]
    assert len(collapsed[2].alloc_events) == 2
    assert len(collapsed[3].free_events) == 2
    assert {event.chunk for event in collapsed[3].free_events} == {
        "op_002__content", "op_002__management_struct"
    }


def test_lowest_free_policy_reuses_cleared_slot_without_name_guessing() -> None:
    parents = (
        _alloc("op_001", "0x18"),
        _alloc("op_002", "0x18"),
        _free("op_003", "1"),
        _alloc("op_004", "0x30"),
    )
    target = {"per_op": [
        _create_entry("op_001", 0x18),
        _create_entry("op_002", 0x18),
        _delete_entry("op_003", 1),
        _create_entry("op_004", 0x30),
    ]}
    plan = A.build_replay_plan(parents, target)
    assert [group.handle for group in plan.groups] == ["0", "1", "1", "1"]
    content = next(
        op for op in plan.operations
        if op.op_id == "op_004__tb2"
    )
    assert content.index == "1"
    assert content.meta["bind_handle"] == "true"


def test_reviewed_free_role_must_resolve_to_prior_internal_allocation() -> None:
    parents = (_alloc("op_001", "0x18"), _free("op_002", "0"))
    bad_delete = _delete_entry("op_002", 0)
    bad_delete["actions"][1]["role"] = "mystery_struct"
    target = {"per_op": [_create_entry("op_001", 0x18), bad_delete]}
    try:
        A.build_replay_plan(parents, target)
    except ValueError as error:
        assert "mystery_struct" in str(error)
        assert "known roles" in str(error)
    else:
        raise AssertionError("reviewed free must never guess an unresolved role")


def test_unreviewed_operations_remain_identity_replay() -> None:
    parent = _alloc("op_001", "0x20")
    plan = A.build_replay_plan((parent,), {"per_op": [{
        "op_id": "op_001",
        "kind": "alloc",
        "internals_not_modeled": True,
        "actions": [{"action": "malloc"}],
    }]})
    assert plan.operations == (parent,)
    assert plan.groups[0].reviewed is False
    assert plan.groups[0].child_op_ids == ("op_001",)
