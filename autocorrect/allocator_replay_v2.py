#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cycle-6 allocator replay: TargetBehavior 1:N -> one parent replay step.

The recognizer/canonical layer keeps one operation per EXP helper call.  A
reviewed TargetBehavior entry may contain several internal malloc/free actions.
This module expands those actions only for the allocator engine, replays them in
real order, then collapses the internal snapshots back to the parent canonical
operation.  Therefore the formal artifacts preserve stable parent ``op_id``
identity while one replay step can truthfully contain N allocator events.

No EXP code is executed and no source is reparsed here.  Handle allocation is
performed only when a reviewed ``handle_policy`` is present; missing identity
facts block the reviewed expansion instead of being guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Mapping, Sequence

from pwncraft.features.heapviz.engine import GlibcHeapEngine
from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind

ALLOCATOR_REPLAY_REVISION = "allocator-replay-2026.09-r1"


@dataclass(frozen=True)
class ReplayGroup:
    parent_op_id: str
    parent_operation: HeapOperation
    first_snapshot: int
    last_snapshot: int
    child_op_ids: tuple[str, ...]
    handle: str = ""
    reviewed: bool = False


@dataclass(frozen=True)
class AllocatorReplayPlan:
    operations: tuple[HeapOperation, ...]
    groups: tuple[ReplayGroup, ...]
    revision: str = ALLOCATOR_REPLAY_REVISION

    @property
    def expanded_parent_count(self) -> int:
        return sum(1 for group in self.groups if len(group.child_op_ids) > 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "expanded_operation_count": len(self.operations),
            "parent_operation_count": len(self.groups),
            "expanded_parent_count": self.expanded_parent_count,
            "groups": [
                {
                    "parent_op_id": group.parent_op_id,
                    "child_op_ids": list(group.child_op_ids),
                    "handle": group.handle,
                    "reviewed": group.reviewed,
                }
                for group in self.groups
            ],
        }


def _abstract_text(value: object) -> str:
    if isinstance(value, Mapping):
        kind = str(value.get("kind") or "")
        if kind == "concrete":
            raw = value.get("value", value.get("ConcreteInt"))
            try:
                numeric = int(raw)  # bool intentionally normalizes to 0/1
            except (TypeError, ValueError):
                return str(raw or value.get("source") or "")
            return hex(numeric)
        if kind == "symbolic":
            return str(
                value.get("expression")
                or value.get("SymbolicInt")
                or value.get("source")
                or ""
            )
        return str(value.get("source") or "")
    return str(value or "").strip()


def _safe_role(role: object, fallback: str) -> str:
    text = str(role or fallback).strip() or fallback
    text = re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_")
    return text or fallback


def _policy_handle(
    policy: object,
    active: Mapping[str, Mapping[str, str]],
) -> str:
    if not isinstance(policy, Mapping):
        return ""
    kind = str(policy.get("kind") or "")
    if kind != "lowest_free_index":
        return ""
    try:
        limit = int(policy.get("limit") or 0)
    except (TypeError, ValueError):
        return ""
    for index in range(max(0, limit)):
        handle = str(index)
        if handle not in active:
            return handle
    raise ValueError(
        f"reviewed handle policy lowest_free_index exhausted (limit={limit})"
    )


def _parent_handle(
    operation: HeapOperation,
    entry: Mapping[str, Any],
    active: Mapping[str, Mapping[str, str]],
) -> str:
    explicit = str(operation.index or "").strip()
    if explicit:
        return explicit
    return _policy_handle(entry.get("handle_policy"), active)


def _alloc_children(
    parent: HeapOperation,
    entry: Mapping[str, Any],
    active: dict[str, dict[str, str]],
) -> tuple[list[HeapOperation], str]:
    actions = [
        dict(action) for action in (entry.get("actions") or [])
        if isinstance(action, Mapping) and str(action.get("action") or "") == "malloc"
    ]
    if not actions:
        return [parent], ""

    handle = _parent_handle(parent, entry, active)
    if not handle and any(bool(action.get("bind_handle", True)) for action in actions):
        raise ValueError(
            f"{parent.op_id}: reviewed malloc expansion needs a proven handle "
            "(canonical index or reviewed handle_policy)"
        )

    role_map: dict[str, str] = {}
    children: list[HeapOperation] = []
    for position, action in enumerate(actions, 1):
        role = _safe_role(action.get("role"), f"malloc_{position}")
        chunk_id = f"{parent.op_id}__{role}"
        if chunk_id in role_map.values():
            chunk_id = f"{chunk_id}_{position}"
        bind_handle = bool(action.get("bind_handle", True))
        request = _abstract_text(action.get("request"))
        child = HeapOperation(
            op_id=f"{parent.op_id}__tb{position}",
            kind=HeapOperationKind.ALLOC,
            chunk=chunk_id,
            index=handle if bind_handle else "",
            request_size=request,
            data=parent.data if bind_handle else "",
            note=str(action.get("note") or parent.note or ""),
            meta={
                **dict(parent.meta),
                "target_behavior_parent": parent.op_id,
                "target_behavior_role": role,
                "bind_handle": "true" if bind_handle else "false",
                "allocator_replay_revision": ALLOCATOR_REPLAY_REVISION,
            },
        )
        children.append(child)
        if handle:
            role_map[role] = chunk_id

    if handle:
        active[handle] = role_map
    return children, handle


def _free_children(
    parent: HeapOperation,
    entry: Mapping[str, Any],
    active: dict[str, dict[str, str]],
) -> tuple[list[HeapOperation], str]:
    actions = [
        dict(action) for action in (entry.get("actions") or [])
        if isinstance(action, Mapping) and str(action.get("action") or "") == "free"
    ]
    if not actions:
        return [parent], ""

    handle = str(parent.index or "").strip()
    if not handle and actions:
        handle = _abstract_text(actions[0].get("target"))
    if not handle:
        raise ValueError(f"{parent.op_id}: reviewed free expansion has no proven handle")
    role_map = active.get(handle)
    if not role_map:
        raise ValueError(
            f"{parent.op_id}: reviewed free references handle {handle}, "
            "but no reviewed internal allocations are active for that handle"
        )

    children: list[HeapOperation] = []
    for position, action in enumerate(actions, 1):
        role = _safe_role(action.get("role"), f"free_{position}")
        chunk_id = role_map.get(role, "")
        if not chunk_id:
            raise ValueError(
                f"{parent.op_id}: reviewed free role {role!r} cannot be resolved "
                f"for handle {handle}; known roles={sorted(role_map)}"
            )
        children.append(HeapOperation(
            op_id=f"{parent.op_id}__tb{position}",
            kind=HeapOperationKind.FREE,
            chunk=chunk_id,
            note=str(action.get("note") or parent.note or ""),
            meta={
                **dict(parent.meta),
                "target_behavior_parent": parent.op_id,
                "target_behavior_role": role,
                "allocator_replay_revision": ALLOCATOR_REPLAY_REVISION,
            },
        ))

    # The reviewed target call itself clears the logical object/slot only after
    # all of its internal frees.  The engine executes children in that order.
    active.pop(handle, None)
    return children, handle


def build_replay_plan(
    parent_operations: Sequence[HeapOperation],
    target_behavior: Mapping[str, Any],
) -> AllocatorReplayPlan:
    by_op = {
        str(entry.get("op_id") or ""): entry
        for entry in (target_behavior.get("per_op") or [])
        if isinstance(entry, Mapping) and entry.get("op_id")
    }
    active: dict[str, dict[str, str]] = {}
    expanded: list[HeapOperation] = []
    groups: list[ReplayGroup] = []
    snapshot_cursor = 1  # snapshot[0] is the engine initial state

    for parent in parent_operations:
        entry = by_op.get(parent.op_id)
        reviewed = bool(entry and not entry.get("internals_not_modeled", True))
        children: list[HeapOperation] = [parent]
        handle = ""
        if reviewed and parent.kind == HeapOperationKind.ALLOC:
            children, handle = _alloc_children(parent, entry, active)
        elif reviewed and parent.kind == HeapOperationKind.FREE:
            children, handle = _free_children(parent, entry, active)

        first = snapshot_cursor
        expanded.extend(children)
        snapshot_cursor += len(children)
        groups.append(ReplayGroup(
            parent_op_id=parent.op_id,
            parent_operation=parent,
            first_snapshot=first,
            last_snapshot=snapshot_cursor - 1,
            child_op_ids=tuple(child.op_id for child in children),
            handle=handle,
            reviewed=reviewed,
        ))

    return AllocatorReplayPlan(tuple(expanded), tuple(groups))


def _flatten_attr(snapshots: Sequence[Any], attr: str) -> tuple[Any, ...]:
    values: list[Any] = []
    for snapshot in snapshots:
        values.extend(tuple(getattr(snapshot, attr, ()) or ()))
    return tuple(values)


def collapse_snapshots(
    expanded_snapshots: Sequence[Any],
    plan: AllocatorReplayPlan,
) -> tuple[Any, ...]:
    expected = len(plan.operations) + 1
    if len(expanded_snapshots) != expected:
        raise ValueError(
            f"allocator expanded replay snapshot count mismatch: "
            f"got {len(expanded_snapshots)}, expected {expected}"
        )
    collapsed: list[Any] = [expanded_snapshots[0]]
    for parent_step, group in enumerate(plan.groups, 1):
        window = list(expanded_snapshots[group.first_snapshot:group.last_snapshot + 1])
        if not window:
            raise ValueError(f"allocator replay group {group.parent_op_id} has no snapshots")
        final = window[-1]
        focus = tuple(dict.fromkeys(
            chunk for snapshot in window for chunk in (snapshot.focus_chunks or ())
        ))
        collapsed.append(replace(
            final,
            step=parent_step,
            operation_id=group.parent_op_id,
            warnings=_flatten_attr(window, "warnings"),
            explanation=_flatten_attr(window, "explanation"),
            focus_chunks=focus,
            event_title=group.parent_operation.title(),
            intents=_flatten_attr(window, "intents"),
            write_events=_flatten_attr(window, "write_events"),
            overwrite_edges=_flatten_attr(window, "overwrite_edges"),
            read_events=_flatten_attr(window, "read_events"),
            alloc_events=_flatten_attr(window, "alloc_events"),
            free_events=_flatten_attr(window, "free_events"),
            bin_transition_events=_flatten_attr(window, "bin_transition_events"),
        ))
    return tuple(collapsed)


def replay_session(session: Any, target_behavior: Mapping[str, Any]) -> tuple[dict[str, Any], AllocatorReplayPlan]:
    """Replay a loaded HeapSession through reviewed 1:N allocator actions.

    ``session.load`` has already performed the single source analysis.  This
    function reuses only ``session.scenario.operations`` + TargetBehavior; the
    provisional identity replay is discarded and all returned artifacts are
    regenerated from the expanded allocator replay.
    """
    if session.analysis is None:
        raise ValueError("allocator replay requires a loaded HeapSession analysis")
    plan = build_replay_plan(tuple(session.scenario.operations), target_behavior)
    engine = GlibcHeapEngine(session.config(), variables=session.variables())
    expanded_snapshots = engine.replay(plan.operations)
    session.engine = engine
    session.snapshots = list(collapse_snapshots(expanded_snapshots, plan))
    try:
        engine.assert_cache_consistency()
        session._cache_divergence = ""  # formal adapter mirrors HeapSession.replay
    except AssertionError as error:
        session._cache_divergence = str(error)
    return session.state(), plan
