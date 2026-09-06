from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class TypedViewDefinition:
    type_name: str
    title: str
    size: int
    source: str = "bundled"


class TypedViewRegistry:
    def __init__(self, definitions: Iterable[TypedViewDefinition] = ()):
        self._items = {item.type_name: item for item in definitions}

    def register(self, definition: TypedViewDefinition) -> None:
        self._items[definition.type_name] = definition

    def get(self, type_name: str) -> TypedViewDefinition | None:
        return self._items.get(type_name)

    @property
    def definitions(self) -> tuple[TypedViewDefinition, ...]:
        return tuple(self._items.values())


def default_typed_view_registry() -> TypedViewRegistry:
    return TypedViewRegistry((
        TypedViewDefinition("malloc_chunk", "malloc_chunk", 0x20),
        TypedViewDefinition("tcache_entry", "tcache_entry", 0x10),
        TypedViewDefinition("_IO_FILE", "_IO_FILE", 0xD8),
        TypedViewDefinition("_IO_FILE_plus", "_IO_FILE_plus", 0xE0),
        TypedViewDefinition("_IO_wide_data", "_IO_wide_data", 0xE8),
        TypedViewDefinition("exit_function", "exit_function", 0x20),
        TypedViewDefinition("link_map", "link_map", 0x100),
        TypedViewDefinition("rtld_global", "rtld_global", 0x100),
    ))
