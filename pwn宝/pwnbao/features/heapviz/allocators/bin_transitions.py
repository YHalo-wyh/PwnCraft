from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


ARENA_SENTINEL = "main_arena"


@dataclass(frozen=True)
class LinkMutation:
    """One allocator-owned pointer update caused by a bin transition.

    ``node`` and ``target`` are logical node ids.  The engine resolves them to
    physical addresses.  Keeping the calculation pure makes it testable and,
    more importantly, prevents a refresh pass from silently rebuilding every
    fd/bk word after an EXP has corrupted one of them.
    """

    node: str
    field: str
    target: str
    reason: str = ""


@dataclass(frozen=True)
class DoublyChainTransition:
    action: str
    node: str
    before: tuple[str, ...]
    after: tuple[str, ...]
    mutations: tuple[LinkMutation, ...]


def insert_doubly(
    chain: Iterable[str],
    node: str,
    *,
    at_head: bool,
    sentinel: str = ARENA_SENTINEL,
) -> DoublyChainTransition:
    before = tuple(chain)
    if node in before:
        return DoublyChainTransition("insert-noop", node, before, before, ())
    if at_head:
        old_head = before[0] if before else sentinel
        after = (node, *before)
        mutations = [
            LinkMutation(node, "fd", old_head, "new head points to previous head"),
            LinkMutation(node, "bk", sentinel, "new head points back to bin sentinel"),
            LinkMutation(sentinel, "fd", node, "bin sentinel publishes new head"),
        ]
        if old_head != sentinel:
            mutations.append(LinkMutation(old_head, "bk", node, "previous head links back to new head"))
    else:
        old_tail = before[-1] if before else sentinel
        after = (*before, node)
        mutations = [
            LinkMutation(node, "fd", sentinel, "new tail points to bin sentinel"),
            LinkMutation(node, "bk", old_tail, "new tail points back to previous tail"),
            LinkMutation(sentinel, "bk", node, "bin sentinel publishes new tail"),
        ]
        if old_tail != sentinel:
            mutations.append(LinkMutation(old_tail, "fd", node, "previous tail points to new tail"))
    if not before:
        # An empty circular list publishes the same node as both head and tail.
        extra_field = "bk" if at_head else "fd"
        mutations.append(LinkMutation(sentinel, extra_field, node, "empty bin publishes both ends"))
    return DoublyChainTransition("insert-head" if at_head else "insert-tail", node, before, tuple(after), tuple(mutations))


def remove_doubly(
    chain: Iterable[str],
    node: str,
    *,
    sentinel: str = ARENA_SENTINEL,
) -> DoublyChainTransition:
    before = tuple(chain)
    if node not in before:
        return DoublyChainTransition("remove-missing", node, before, before, ())
    index = before.index(node)
    previous = before[index - 1] if index > 0 else sentinel
    following = before[index + 1] if index + 1 < len(before) else sentinel
    after = before[:index] + before[index + 1 :]
    mutations = (
        LinkMutation(previous, "fd", following, "unlink bypasses removed node"),
        LinkMutation(following, "bk", previous, "unlink repairs backward link"),
    )
    return DoublyChainTransition("remove", node, before, after, mutations)


__all__ = [
    "ARENA_SENTINEL",
    "DoublyChainTransition",
    "LinkMutation",
    "insert_doubly",
    "remove_doubly",
]
