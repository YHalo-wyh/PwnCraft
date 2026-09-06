from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from pwncraft.features.heapviz.semantics import CanonicalHeapOperation


@dataclass(frozen=True)
class ReplayDependency:
    operation_id: str
    checkpoint: int
    source_id: str = ""
    contract_id: str = ""
    symbols: tuple[str, ...] = ()
    physical_objects: tuple[str, ...] = ()


class ReplayDependencyIndex:
    """Deterministic earliest-checkpoint index for incremental replay."""

    def __init__(self, dependencies: Iterable[ReplayDependency] = ()) -> None:
        self._dependencies = tuple(sorted(dependencies, key=lambda item: item.checkpoint))

    @classmethod
    def from_operations(cls, operations: Iterable[CanonicalHeapOperation]) -> ReplayDependencyIndex:
        return cls(
            ReplayDependency(
                operation.operation_id,
                checkpoint=index,
                source_id=operation.source_binding.source_id,
                contract_id=operation.contract_id,
                symbols=tuple(dict.fromkeys(
                    dependency
                    for value in (operation.handle, operation.menu_request, operation.offset, operation.payload)
                    for dependency in getattr(value, "dependencies", ())
                )),
            )
            for index, operation in enumerate(operations, 1)
        )

    @property
    def dependencies(self) -> tuple[ReplayDependency, ...]:
        return self._dependencies

    def earliest_checkpoint(
        self,
        *,
        source_ids: Iterable[str] = (),
        contract_ids: Iterable[str] = (),
        symbols: Iterable[str] = (),
        physical_objects: Iterable[str] = (),
        default: int = 0,
    ) -> int:
        sources = set(source_ids)
        contracts = set(contract_ids)
        symbol_set = set(symbols)
        objects = set(physical_objects)
        matches = [
            item.checkpoint
            for item in self._dependencies
            if (
                (sources and item.source_id in sources)
                or (contracts and item.contract_id in contracts)
                or (symbol_set and symbol_set.intersection(item.symbols))
                or (objects and objects.intersection(item.physical_objects))
            )
        ]
        return min(matches, default=default)

    def suffix_operation_ids(self, checkpoint: int) -> tuple[str, ...]:
        return tuple(
            item.operation_id
            for item in self._dependencies
            if item.checkpoint >= checkpoint
        )
