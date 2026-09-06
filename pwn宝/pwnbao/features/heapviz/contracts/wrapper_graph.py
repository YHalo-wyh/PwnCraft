from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WrapperEdge:
    caller: str
    callee: str
    argument_transform: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class HelperCallGraph:
    edges: tuple[WrapperEdge, ...] = ()

    def outgoing(self, helper: str) -> tuple[WrapperEdge, ...]:
        return tuple(item for item in self.edges if item.caller == helper)

    def affected_by(self, helper: str) -> tuple[str, ...]:
        affected = {helper}
        changed = True
        while changed:
            changed = False
            for edge in self.edges:
                if edge.callee in affected and edge.caller not in affected:
                    affected.add(edge.caller)
                    changed = True
        return tuple(sorted(affected))
