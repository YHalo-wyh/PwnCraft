from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Iterable, Mapping


@dataclass(frozen=True)
class CanvasObjectLayout:
    object_id: str
    x: float
    y: float
    width: float = 320.0
    height: float = 168.0
    collapsed: bool = False
    locked: bool = False
    z_order: int = 0
    group_id: str = ""
    layout_key: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LayoutCommand:
    before: dict[str, CanvasObjectLayout]
    after: dict[str, CanvasObjectLayout]
    description: str = "layout"


class CanvasLayoutModel:
    """Persistent draw.io-like geometry; never stores heap addresses or bytes."""

    def __init__(self, layouts: Iterable[CanvasObjectLayout] = ()) -> None:
        self._items = {item.object_id: item for item in layouts}
        self._selection: set[str] = set()
        self._undo: list[LayoutCommand] = []
        self._redo: list[LayoutCommand] = []

    @property
    def layouts(self) -> tuple[CanvasObjectLayout, ...]:
        return tuple(sorted(self._items.values(), key=lambda item: (item.z_order, item.object_id)))

    @property
    def selected_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._selection))

    def get(self, object_id: str) -> CanvasObjectLayout | None:
        return self._items.get(object_id)

    def ensure(self, object_id: str, x: float = 0.0, y: float = 0.0, width: float = 320.0, height: float = 168.0, layout_key: Mapping[str, str] | None = None) -> CanvasObjectLayout:
        item = self._items.get(object_id)
        if item is None:
            item = CanvasObjectLayout(object_id, x, y, max(96.0, width), max(64.0, height), z_order=len(self._items), layout_key=dict(layout_key or {}))
            self._items[object_id] = item
        return item

    def refresh_geometry(
        self,
        object_id: str,
        x: float,
        y: float,
        width: float,
        height: float,
        *,
        preserve_position: bool = False,
        preserve_size: bool = False,
    ) -> CanvasObjectLayout:
        """Refresh responsive geometry without creating an undo command."""
        item = self.ensure(object_id, x, y, width, height)
        updated = replace(
            item,
            x=item.x if preserve_position else x,
            y=item.y if preserve_position else y,
            width=item.width if preserve_size else max(96.0, width),
            height=item.height if preserve_size else max(64.0, height),
        )
        self._items[object_id] = updated
        return updated

    def rebind(self, key_of: Mapping[str, str]) -> int:
        """Replay 后 chunk_id 可能变化：按语义 key 迁移旧几何到新 id（requirement 192/193）。

        ``key_of`` 把新 object_id 映射到语义 key（physical lineage + allocation call id）。
        若当前模型里存在相同语义 key 的旧条目，则复制其几何（x/y/width/height/collapsed），
        object_id 换成新 id。返回迁移条目数。
        """
        key_to_old: dict[str, str] = {}
        for old_id, item in self._items.items():
            semantic = item.layout_key.get("semantic_key", "")
            if semantic:
                key_to_old.setdefault(semantic, old_id)
        replacements: dict[str, CanvasObjectLayout] = {}
        for new_id, semantic in key_of.items():
            if not semantic:
                continue
            old_id = key_to_old.get(semantic)
            if old_id is None or old_id == new_id or new_id in self._items:
                continue
            old = self._items[old_id]
            replacements[new_id] = replace(old, object_id=new_id, layout_key={**old.layout_key, "semantic_key": semantic})
        if replacements:
            self._items.update(replacements)
        return len(replacements)

    def select(self, object_ids: Iterable[str], additive: bool = False) -> None:
        if not additive:
            self._selection.clear()
        self._selection.update(item for item in object_ids if item in self._items)

    def marquee_select(self, x: float, y: float, width: float, height: float, additive: bool = False) -> tuple[str, ...]:
        right, bottom = x + width, y + height
        hits = [
            item.object_id for item in self._items.values()
            if item.x < right and item.x + item.width > x and item.y < bottom and item.y + item.height > y
        ]
        self.select(hits, additive)
        return tuple(sorted(hits))

    def move(self, object_ids: Iterable[str], dx: float, dy: float) -> LayoutCommand | None:
        ids = tuple(dict.fromkeys(object_ids))
        return self._change(ids, lambda item: replace(item, x=item.x + dx, y=item.y + dy), "move")

    def resize(self, object_id: str, width: float, height: float) -> LayoutCommand | None:
        return self._change((object_id,), lambda item: replace(item, width=max(96.0, width), height=max(64.0, height)), "resize")

    def update_interactive_geometry(
        self,
        object_id: str,
        *,
        x: float,
        y: float,
        width: float,
        height: float,
    ) -> CanvasObjectLayout | None:
        """Update draw-only geometry during a handle drag, without heap work."""
        item = self._items.get(object_id)
        if item is None or item.locked:
            return None
        updated = replace(
            item,
            x=float(x),
            y=float(y),
            width=max(96.0, float(width)),
            height=max(64.0, float(height)),
        )
        self._items[object_id] = updated
        return updated

    def commit_interactive_geometry(
        self,
        before: CanvasObjectLayout,
        description: str = "resize-handle",
    ) -> LayoutCommand | None:
        after = self._items.get(before.object_id)
        if after is None or after == before:
            return None
        command = LayoutCommand({before.object_id: before}, {before.object_id: after}, description)
        self._undo.append(command)
        self._redo.clear()
        return command

    def set_locked(self, object_ids: Iterable[str], locked: bool) -> LayoutCommand | None:
        return self._change(tuple(object_ids), lambda item: replace(item, locked=locked), "lock")

    def set_collapsed(self, object_ids: Iterable[str], collapsed: bool) -> LayoutCommand | None:
        return self._change(tuple(object_ids), lambda item: replace(item, collapsed=collapsed), "collapse")

    def align(self, object_ids: Iterable[str], edge: str) -> LayoutCommand | None:
        ids = tuple(item for item in object_ids if item in self._items)
        items = [self._items[item] for item in ids]
        if len(items) < 2:
            return None
        if edge == "left":
            value = min(item.x for item in items)
        elif edge == "right":
            value = max(item.x + item.width for item in items)
        elif edge == "top":
            value = min(item.y for item in items)
        elif edge == "bottom":
            value = max(item.y + item.height for item in items)
        elif edge == "center_x":
            value = sum(item.x + item.width / 2 for item in items) / len(items)
        elif edge == "center_y":
            value = sum(item.y + item.height / 2 for item in items) / len(items)
        else:
            raise ValueError(f"unknown alignment: {edge}")

        def transform(item: CanvasObjectLayout) -> CanvasObjectLayout:
            if edge == "left":
                return replace(item, x=value)
            if edge == "right":
                return replace(item, x=value - item.width)
            if edge == "top":
                return replace(item, y=value)
            if edge == "bottom":
                return replace(item, y=value - item.height)
            if edge == "center_x":
                return replace(item, x=value - item.width / 2)
            return replace(item, y=value - item.height / 2)

        return self._change(ids, transform, f"align:{edge}")

    def distribute(self, object_ids: Iterable[str], axis: str) -> LayoutCommand | None:
        ids = tuple(item for item in object_ids if item in self._items)
        items = [self._items[item] for item in ids]
        if len(items) < 3:
            return None
        if axis == "horizontal":
            ordered = sorted(items, key=lambda item: item.x)
            first, last = ordered[0].x, ordered[-1].x
            positions = {item.object_id: first + index * (last - first) / (len(ordered) - 1) for index, item in enumerate(ordered)}
        elif axis == "vertical":
            ordered = sorted(items, key=lambda item: item.y)
            first, last = ordered[0].y, ordered[-1].y
            positions = {item.object_id: first + index * (last - first) / (len(ordered) - 1) for index, item in enumerate(ordered)}
        else:
            raise ValueError(f"unknown distribution axis: {axis}")

        def transform(item: CanvasObjectLayout) -> CanvasObjectLayout:
            if axis == "horizontal":
                return replace(item, x=positions[item.object_id])
            return replace(item, y=positions[item.object_id])

        return self._change(ids, transform, f"distribute:{axis}")

    def copy_layout(self, source_id: str, target_ids: Iterable[str]) -> LayoutCommand | None:
        source = self._items.get(source_id)
        if source is None:
            return None
        return self._change(
            tuple(target_ids),
            lambda item: replace(item, width=source.width, height=source.height, collapsed=source.collapsed),
            "copy layout",
        )

    def auto_layout(self, object_ids: Iterable[str] | None = None, columns: int = 2, gap: float = 28.0) -> LayoutCommand | None:
        ids = tuple(object_ids or sorted(self._items))
        before = {item: self._items[item] for item in ids if item in self._items}
        if not before:
            return None
        columns = max(1, columns)
        after: dict[str, CanvasObjectLayout] = {}
        for index, object_id in enumerate(ids):
            item = before.get(object_id)
            if item is None or item.locked:
                continue
            column, row = index % columns, index // columns
            after[object_id] = replace(item, x=24.0 + column * (item.width + gap), y=56.0 + row * (item.height + gap))
        return self._commit(before, after, "auto layout")

    def physical_layout(self, addresses: Mapping[str, int], x: float = 24.0, y: float = 56.0, gap: float = 20.0) -> LayoutCommand | None:
        ordered = sorted((object_id for object_id in addresses if object_id in self._items), key=lambda item: (addresses[item], item))
        before = {item: self._items[item] for item in ordered}
        cursor = y
        after: dict[str, CanvasObjectLayout] = {}
        for object_id in ordered:
            item = before[object_id]
            if not item.locked:
                after[object_id] = replace(item, x=x, y=cursor)
            cursor += item.height + gap
        return self._commit(before, after, "physical layout")

    def undo(self) -> LayoutCommand | None:
        if not self._undo:
            return None
        command = self._undo.pop()
        self._items.update(command.before)
        self._redo.append(command)
        return command

    def redo(self) -> LayoutCommand | None:
        if not self._redo:
            return None
        command = self._redo.pop()
        self._items.update(command.after)
        self._undo.append(command)
        return command

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": 1, "objects": [asdict(item) for item in self.layouts]}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> CanvasLayoutModel:
        return cls(CanvasObjectLayout(**dict(item)) for item in list(payload.get("objects") or []))

    def save(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(target)

    @classmethod
    def load(cls, path: str | Path) -> CanvasLayoutModel:
        target = Path(path)
        return cls.from_dict(json.loads(target.read_text(encoding="utf-8"))) if target.exists() else cls()

    def _change(self, ids: tuple[str, ...], transform: object, description: str) -> LayoutCommand | None:
        before = {item: self._items[item] for item in ids if item in self._items}
        after = {
            object_id: transform(item)  # type: ignore[operator]
            for object_id, item in before.items()
            if not item.locked
        }
        return self._commit(before, after, description)

    def _commit(
        self,
        before: dict[str, CanvasObjectLayout],
        after: dict[str, CanvasObjectLayout],
        description: str,
    ) -> LayoutCommand | None:
        changed_before = {key: value for key, value in before.items() if after.get(key, value) != value}
        changed_after = {key: after[key] for key in changed_before}
        if not changed_before:
            return None
        command = LayoutCommand(changed_before, changed_after, description)
        self._items.update(changed_after)
        self._undo.append(command)
        self._redo.clear()
        return command
