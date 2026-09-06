from __future__ import annotations

from dataclasses import dataclass, field, replace

from .layouts import GlibcFileLayout


@dataclass(frozen=True)
class FileFieldValue:
    name: str
    value: int | None = None
    raw: bytes = b""
    provenance: str = "unknown"


@dataclass(frozen=True)
class FileSnapshot:
    snapshot_id: str
    origin: str
    layout: GlibcFileLayout
    address: int | None = None
    symbol: str = "stdout"
    fields: dict[str, FileFieldValue] = field(default_factory=dict)
    wide_fields: dict[str, FileFieldValue] = field(default_factory=dict)
    backing_range: tuple[int, int] | None = None
    memory_revision: int = 0

    @classmethod
    def empty(cls, layout: GlibcFileLayout, symbol: str = "stdout") -> "FileSnapshot":
        return cls(
            f"static:{symbol}:0",
            "STATIC",
            layout,
            symbol=symbol,
            fields={item.name: FileFieldValue(item.name) for item in layout.fields},
            wide_fields={item.name: FileFieldValue(item.name) for item in layout.wide_fields},
        )

    def edit(self, name: str, value: int, provenance: str = "corrected") -> "FileSnapshot":
        revision = self.memory_revision + 1
        target = dict(self.wide_fields if name.startswith("wide.") else self.fields)
        target[name] = FileFieldValue(name, value, value.to_bytes(self.layout.field(name).width, "little"), provenance)
        kwargs = {"wide_fields": target} if name.startswith("wide.") else {"fields": target}
        return replace(
            self,
            snapshot_id=f"corrected:{self.symbol}:{revision}",
            origin="CORRECTED",
            memory_revision=revision,
            **kwargs,
        )
