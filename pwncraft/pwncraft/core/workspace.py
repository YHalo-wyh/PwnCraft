from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping


class AddressKind(str, Enum):
    STATIC_ADDRESS = "STATIC_ADDRESS"
    PIE_OFFSET = "PIE_OFFSET"
    LIBC_OFFSET = "LIBC_OFFSET"
    HEAP_OFFSET = "HEAP_OFFSET"
    RUNTIME_ADDRESS = "RUNTIME_ADDRESS"
    SYMBOL_ADDRESS = "SYMBOL_ADDRESS"
    GADGET_ADDRESS = "GADGET_ADDRESS"


@dataclass(frozen=True)
class TypedAddress:
    """An address plus its semantic coordinate system."""

    value: int | str
    kind: AddressKind
    module: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AddressKind):
            try:
                object.__setattr__(self, "kind", AddressKind(str(self.kind).strip().upper()))
            except ValueError as exc:
                raise ValueError(f"未知地址类型: {self.kind}") from exc

    def format(self) -> str:
        return f"{self.value:#x}" if isinstance(self.value, int) else str(self.value)

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value, "kind": self.kind.value, "module": self.module}

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "TypedAddress":
        raw_value = payload.get("value", "")
        value: int | str = raw_value if isinstance(raw_value, (int, str)) else str(raw_value)
        if isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                pass
        raw_kind = str(payload.get("kind", AddressKind.STATIC_ADDRESS.value))
        try:
            kind = AddressKind(raw_kind)
        except ValueError:
            kind = AddressKind.STATIC_ADDRESS
        return cls(value, kind, str(payload.get("module", "")))


@dataclass(frozen=True)
class WorkspaceVariable:
    name: str
    value: object
    source: str
    evidence: str = ""
    state: str = "confirmed"
    formula: str = ""
    address_kind: AddressKind | None = None

    def __post_init__(self) -> None:
        if not str(self.name).strip():
            raise ValueError("Workspace 变量名不能为空")

    def to_dict(self) -> dict[str, object]:
        value = self.value.to_dict() if isinstance(self.value, TypedAddress) else _json_value(self.value)
        return {
            "name": self.name,
            "value": value,
            "source": self.source,
            "evidence": self.evidence,
            "state": self.state,
            "formula": self.formula,
            "address_kind": self.address_kind.value if self.address_kind else None,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object], *, fallback_name: str = "") -> "WorkspaceVariable":
        name = str(payload.get("name", fallback_name))
        raw_value = payload.get("value")
        if isinstance(raw_value, Mapping) and "kind" in raw_value:
            value: object = TypedAddress.from_dict(raw_value)
        else:
            value = raw_value
        raw_kind = payload.get("address_kind")
        address_kind = None
        if raw_kind:
            try:
                address_kind = AddressKind(str(raw_kind))
            except ValueError:
                address_kind = None
        return cls(
            name=name,
            value=value,
            source=str(payload.get("source", "")),
            evidence=str(payload.get("evidence", "")),
            state=str(payload.get("state", "confirmed")),
            formula=str(payload.get("formula", "")),
            address_kind=address_kind,
        )


Listener = Callable[[dict[str, object]], None]


class WorkspaceEventBus:
    """Small synchronous event bus used to avoid full UI redraws."""

    def __init__(self) -> None:
        self._listeners: dict[str, list[Listener]] = {}

    def subscribe(self, event: str, callback: Listener) -> None:
        listeners = self._listeners.setdefault(str(event), [])
        if callback not in listeners:
            listeners.append(callback)

    def unsubscribe(self, event: str, callback: Listener) -> None:
        listeners = self._listeners.get(str(event), [])
        if callback in listeners:
            listeners.remove(callback)

    def publish(self, event: str, **payload: object) -> None:
        for callback in tuple(self._listeners.get(str(event), ())):
            callback(dict(payload))


@dataclass
class PwnWorkspace:
    project: dict[str, object] = field(default_factory=dict)
    target: dict[str, object] = field(default_factory=dict)
    binary: dict[str, object] = field(default_factory=dict)
    symbols: dict[str, object] = field(default_factory=dict)
    runtime: dict[str, object] = field(default_factory=dict)
    libraries: dict[str, object] = field(default_factory=dict)
    gadgets: dict[str, object] = field(default_factory=lambda: {"discovered": [], "pinned": [], "semantic_index": {}})
    syscalls: dict[str, object] = field(default_factory=lambda: {"architecture_table": {}, "seccomp_policy": {}})
    leaks: list[dict[str, object]] = field(default_factory=list)
    heap: dict[str, object] = field(default_factory=dict)
    stack: dict[str, object] = field(default_factory=dict)
    exploit: dict[str, object] = field(default_factory=lambda: {"variables": {}, "stages": [], "chains": [], "primitives": [], "goals": []})
    notes: list[str] = field(default_factory=list)
    variables: dict[str, WorkspaceVariable] = field(default_factory=dict, repr=False)
    _events: WorkspaceEventBus = field(default_factory=WorkspaceEventBus, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.project.setdefault("created_at", _now())
        self.project.setdefault("updated_at", self.project["created_at"])
        # Be tolerant of older project files that omitted newly introduced
        # collection keys.
        for section, default in _workspace_defaults().items():
            if section not in self.__dict__:
                setattr(self, section, _clone_json(default))

    def subscribe(self, event: str, callback: Listener) -> None:
        self._events.subscribe(event, callback)

    def unsubscribe(self, event: str, callback: Listener) -> None:
        self._events.unsubscribe(event, callback)

    def set_variable(self, variable: WorkspaceVariable) -> None:
        self.variables[variable.name] = variable
        self._touch()
        self._events.publish("variable_changed", name=variable.name, variable=variable.to_dict())

    def get_variable(self, name: str) -> WorkspaceVariable | None:
        return self.variables.get(str(name).strip())

    def remove_variable(self, name: str) -> WorkspaceVariable | None:
        variable = self.variables.pop(str(name).strip(), None)
        if variable is not None:
            self._touch()
            self._events.publish("variable_removed", name=variable.name)
        return variable

    def update_section(self, section: str, value: Mapping[str, object], event: str | None = None) -> None:
        if not hasattr(self, section) or section in {"variables", "_events"}:
            raise ValueError(f"未知 Workspace 区域: {section}")
        target = getattr(self, section)
        if not isinstance(target, dict):
            raise ValueError(f"Workspace 区域不可合并: {section}")
        target.update(dict(value))
        self._touch()
        self._events.publish(event or f"{section}_changed", section=section, value=dict(value))

    def set_binary(self, **facts: object) -> None:
        self.update_section("binary", facts, event="binary_loaded")

    def set_target(self, context: object) -> dict[str, object]:
        """Publish the single TargetContext (v0.20 §1); mirror to binary.

        The TargetContext is the only user-facing target truth; the legacy
        ``binary`` section keeps receiving a derived mirror so pages and
        saved projects from earlier versions stay readable during the
        migration (full removal is Phase F).
        """
        from .session.target import TargetContext

        if not isinstance(context, TargetContext):
            raise TypeError("set_target 需要 TargetContext 实例")
        payload = context.to_dict()
        self.target = payload
        mirror = {
            "path": context.primary_path,
            "original_path": context.original_binary,
            "working_path": context.working_binary,
            "sha256": context.sha256,
            "architecture": context.architecture,
            "bits": context.bits,
            "endian": context.endian,
            "entry": context.entry,
            "libc": context.libc,
            "ld": context.ld,
            "build_id": context.build_id,
            "target_id": context.target_id,
        }
        self.update_section("binary", mirror, event="binary_loaded")
        self._touch()
        self._events.publish("target_changed", target_id=context.target_id)
        return payload

    def get_target(self) -> dict[str, object]:
        return dict(self.target) if isinstance(self.target, dict) else {}

    def set_exploit_source(self, source: str) -> None:
        """Store the editable EXP document without creating a second source of truth."""
        text = str(source)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if self.exploit.get("source") == text and self.exploit.get("source_hash") == digest:
            return
        self.exploit.update({"source": text, "source_hash": digest, "source_state": "editable"})
        self._touch()
        self._events.publish(
            "exploit_source_changed",
            source_hash=digest,
            length=len(text),
            source_state="editable",
        )

    def set_runtime(self, *, observed: bool = True, **facts: object) -> None:
        payload = dict(facts)
        payload["state"] = "observed" if observed else str(payload.get("state", "inferred"))
        self.update_section("runtime", payload, event="runtime_changed")

    def set_heap_snapshot(self, snapshot: Mapping[str, object], *, origin: str = "STATIC") -> None:
        """Publish the current Heap model summary for other Workbench views.

        The allocator model remains the owner of detailed objects.  Workspace
        stores only JSON-safe display facts so Binary/EXP/Debugger pages can
        react without importing HeapViz internals.
        """
        payload = _json_value(dict(snapshot))
        if not isinstance(payload, dict):
            raise ValueError("Heap snapshot 必须是对象")
        payload["origin"] = str(origin)
        # Preserve allocator configuration and any audit metadata already in
        # the section; replace only the current projection fields.
        self.heap.update(payload)
        self._touch()
        self._events.publish("heap_changed", step=payload.get("step"), origin=str(origin))

    def set_gadgets(self, gadgets: object, *, source: str = "") -> None:
        items = []
        try:
            iterator = iter(gadgets)  # type: ignore[arg-type]
        except TypeError:
            iterator = iter(())
        for gadget in iterator:
            if hasattr(gadget, "to_dict"):
                item = gadget.to_dict()
            elif isinstance(gadget, Mapping):
                item = dict(gadget)
            else:
                continue
            if source and not item.get("source"):
                item["source"] = source
            items.append(item)
        self.gadgets["discovered"] = items
        self._touch()
        self._events.publish("gadgets_changed", count=len(items), source=source)

    def pin_gadget(self, role: str, gadget: object) -> None:
        if not str(role).strip() or not hasattr(gadget, "to_dict"):
            raise ValueError("Gadget 角色和值不能为空")
        pinned = self.gadgets.setdefault("pinned", [])
        if not isinstance(pinned, list):
            pinned = []
            self.gadgets["pinned"] = pinned
        pinned[:] = [item for item in pinned if not isinstance(item, Mapping) or item.get("role") != str(role).strip()]
        pinned.append({"role": str(role).strip(), "gadget": gadget.to_dict()})
        self._touch()
        self._events.publish("gadget_pinned", role=str(role).strip())

    def unpin_gadget(self, role: str) -> dict[str, object] | None:
        key = str(role).strip().lower()
        if not key:
            raise ValueError("Gadget 角色不能为空")
        pinned = self.gadgets.setdefault("pinned", [])
        removed: dict[str, object] | None = None
        kept: list[object] = []
        for item in pinned:
            if removed is None and isinstance(item, Mapping) and str(item.get("role", "")).lower() == key:
                removed = dict(item)
                continue
            kept.append(item)
        if removed is None:
            return None
        self.gadgets["pinned"] = kept
        self._touch()
        self._events.publish("gadget_unpinned", role=key)
        return removed

    def merge_saved(self, payload: Mapping[str, object]) -> None:
        """Merge a saved .pwncraft payload into this live workspace instance.

        Sections are replaced wholesale from the file; runtime facts stay
        marked stale.  This keeps object identity (and therefore every
        existing subscription) valid while restoring static analysis state.
        """
        for section in _workspace_defaults():
            raw = payload.get(section)
            if isinstance(raw, Mapping):
                target = getattr(self, section)
                if isinstance(target, dict):
                    replaced = _clone_json(dict(raw))
                    target.clear()
                    target.update(replaced)
            elif isinstance(raw, list) and isinstance(getattr(self, section), list):
                setattr(self, section, _clone_json(raw))
        raw_variables = payload.get("variables")
        if isinstance(raw_variables, Mapping):
            self.variables.clear()
            for name, raw in raw_variables.items():
                if isinstance(raw, Mapping):
                    self.variables[str(name)] = WorkspaceVariable.from_dict(raw, fallback_name=str(name))
        self.mark_runtime_stale(reason="project_reloaded")
        self._touch()
        self._events.publish("workspace_merged")

    def set_seccomp_policy(self, policy: Mapping[str, object], *, source: str = "") -> None:
        self.syscalls["seccomp_policy"] = dict(policy)
        if source:
            self.syscalls["seccomp_source"] = source
        self._touch()
        self._events.publish("seccomp_changed", policy=dict(policy), source=source)

    # ------------------------------------------------------------------
    # Exploit-engine sections (Phase 2): leaks, bases and the shared chain.

    def add_leak(self, *, symbol: str, address: object = None, raw_hex: str = "", source: str = "", confidence: str = "confirmed", note: str = "") -> dict[str, object]:
        from .leaks import Leak

        leak = Leak(str(symbol), address, str(raw_hex), str(source), "", str(confidence), str(note))
        entry = leak.to_dict()
        self.leaks.append(entry)
        self._touch()
        self._events.publish("leaks_changed", symbol=leak.symbol)
        return entry

    def update_leak(self, index: int, **fields: object) -> dict[str, object] | None:
        from .leaks import Leak

        if not 0 <= int(index) < len(self.leaks):
            return None
        merged = dict(self.leaks[int(index)])
        merged.update({key: value for key, value in fields.items() if key in merged})
        self.leaks[int(index)] = Leak.from_dict(merged).to_dict()
        self._touch()
        self._events.publish("leaks_changed", symbol=str(merged.get("symbol", "")))
        return self.leaks[int(index)]

    def set_libc_base(self, value: int, *, formula: str, source: str = "derived") -> None:
        self.libraries["libc_base"] = int(value)
        self.libraries["libc_base_formula"] = str(formula)
        self.libraries["libc_base_source"] = str(source)
        self.set_variable(
            WorkspaceVariable(
                "libc_base",
                TypedAddress(int(value), AddressKind.RUNTIME_ADDRESS, module="libc"),
                source,
                f"formula: {formula}",
                formula=str(formula),
                address_kind=AddressKind.RUNTIME_ADDRESS,
            )
        )
        self._touch()
        self._events.publish("libc_base_changed", value=int(value), formula=str(formula))

    def set_current_chain(self, chain: object, *, title: str = "current") -> dict[str, object]:
        """Publish and validate the shared Chain consumed by Stack Canvas."""
        from .rop import ROPChain

        payload = chain.to_dict() if hasattr(chain, "to_dict") else dict(chain)  # type: ignore[union-attr]
        if not isinstance(payload, dict):
            raise ValueError("chain 必须可序列化")
        try:
            normalized = ROPChain.from_dict(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Chain 数据无效: {exc}") from exc
        if normalized.word_size not in {4, 8}:
            raise ValueError("Chain word_size 必须是 4 或 8")
        for index, entry in enumerate(normalized.entries):
            expected = index * normalized.word_size
            if entry.offset != expected:
                raise ValueError(f"Chain offset 不连续: index={index}, expected={expected:#x}, got={entry.offset:#x}")
        canonical = normalized.to_dict()
        canonical.update({"schema": 1, "title": str(title), "bits": normalized.word_size * 8, "state": "derived"})
        self.stack["current_chain"] = canonical
        self.stack["current_chain_title"] = str(title)
        self._touch()
        self._events.publish("rop_chain_changed", title=str(title), entries=len(normalized.entries))
        return canonical

    def add_stage(
        self,
        title: str,
        *,
        stage_type: str = "custom",
        status: str = "draft",
        inputs: Mapping[str, object] | None = None,
        outputs: Mapping[str, object] | None = None,
        source_code_range: object = None,
        runtime_events: list[object] | None = None,
    ) -> dict[str, object]:
        """Record one explicit exploit stage without executing or guessing it."""
        name = str(title).strip()
        if not name:
            raise ValueError("Stage 标题不能为空")
        stages = self.exploit.setdefault("stages", [])
        if not isinstance(stages, list):
            stages = []
            self.exploit["stages"] = stages
        record = {
            "title": name,
            "type": str(stage_type),
            "status": str(status),
            "inputs": _json_value(dict(inputs or {})),
            "outputs": _json_value(dict(outputs or {})),
            "source_code_range": _json_value(source_code_range),
            "runtime_events": _json_value(list(runtime_events or [])),
            "created_at": _now(),
        }
        stages.append(record)
        self._touch()
        self._events.publish("stages_changed", title=name, total=len(stages))
        return record

    def update_stage(self, index: int, **fields: object) -> dict[str, object] | None:
        stages = self.exploit.setdefault("stages", [])
        if not isinstance(stages, list) or not 0 <= int(index) < len(stages):
            return None
        allowed = {"title", "type", "status", "inputs", "outputs", "source_code_range", "runtime_events"}
        record = stages[int(index)]
        if not isinstance(record, dict):
            return None
        for key, value in fields.items():
            if key in allowed:
                record[key] = _json_value(value)
        self._touch()
        self._events.publish("stages_changed", index=int(index), title=str(record.get("title", "")))
        return record

    def set_libc_symbols(self, symbols: Mapping[str, object], *, source: str = "") -> None:
        """Store libc-file symbol offsets separately from binary symbols."""
        clean: dict[str, int] = {}
        for name, value in dict(symbols).items():
            try:
                clean[str(name)] = int(value, 0) if isinstance(value, str) else int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
        self.libraries["libc_symbols"] = clean
        if source:
            self.libraries["libc_symbols_source"] = str(source)
        self._touch()
        self._events.publish("libc_symbols_changed", count=len(clean), source=str(source))

    def set_one_gadgets(self, gadgets: object, *, source: str = "") -> None:
        if not isinstance(gadgets, list):
            gadgets = [item for item in gadgets] if isinstance(gadgets, (tuple, list)) else []
        self.libraries["one_gadgets"] = gadgets
        if source:
            self.libraries["one_gadgets_source"] = str(source)
        self._touch()
        self._events.publish("one_gadgets_changed", count=len(gadgets), source=str(source))

    def record_heap_stage(self, snapshot: Mapping[str, object], *, title: str = "") -> dict[str, object] | None:
        """Persist a heap snapshot as an exploit-stage input (Phase 5).

        Deduplicates by step so repeated calibration of the same state does
        not spam the stage list; the allocator model stays the detail owner.
        """
        step = snapshot.get("step")
        existing = [item for item in self.exploit.get("stages", []) if isinstance(item, dict) and item.get("type") == "heap"]
        if step is not None and any(item.get("inputs", {}).get("step") == step for item in existing):
            return None
        return self.add_stage(
            title or f"Heap snapshot step {step}",
            stage_type="heap",
            status="recorded",
            inputs=dict(snapshot),
        )

    def add_primitive(self, name: str, *, evidence: str = "", source: str = "manual", state: str = "confirmed") -> dict[str, object]:
        """Record an exploit primitive (规划 §三十三); rules may consume it."""
        label = str(name).strip()
        if not label:
            raise ValueError("Primitive 名称不能为空")
        primitives = self.exploit.setdefault("primitives", [])
        if not isinstance(primitives, list):
            primitives = []
            self.exploit["primitives"] = primitives
        primitives[:] = [item for item in primitives if not isinstance(item, dict) or item.get("name") != label]
        record = {"name": label, "evidence": str(evidence), "source": str(source), "state": str(state)}
        primitives.append(record)
        self._touch()
        self._events.publish("primitives_changed", name=label)
        return record

    def save_chain(self, title: str) -> dict[str, object]:
        payload = self.stack.get("current_chain") if isinstance(self.stack, dict) else None
        if not isinstance(payload, dict) or not payload:
            raise ValueError("当前没有可保存的 Chain；请先构造一条")
        chains = self.exploit.setdefault("chains", [])
        if not isinstance(chains, list):
            chains = []
            self.exploit["chains"] = chains
        record = {"title": str(title), "chain": payload, "saved_at": _now()}
        chains.append(record)
        self._touch()
        self._events.publish("chains_changed", title=str(title), total=len(chains))
        return record

    def mark_runtime_stale(self, reason: str = "workspace_reloaded") -> None:
        if not self.runtime:
            return
        self.runtime["state"] = "stale"
        self.runtime["stale_reason"] = reason
        self._events.publish("runtime_changed", state="stale", reason=reason)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": 2,
            "project": _json_value(self.project),
            "target": _json_value(self.target),
            "binary": _json_value(self.binary),
            "symbols": _json_value(self.symbols),
            "runtime": _json_value(self.runtime),
            "libraries": _json_value(self.libraries),
            "gadgets": _json_value(self.gadgets),
            "syscalls": _json_value(self.syscalls),
            "leaks": _json_value(self.leaks),
            "heap": _json_value(self.heap),
            "stack": _json_value(self.stack),
            "exploit": _json_value(self.exploit),
            "notes": list(self.notes),
            "variables": {name: variable.to_dict() for name, variable in self.variables.items()},
        }

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        if target.suffix.casefold() != ".pwncraft":
            target = target.with_suffix(".pwncraft")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path, *, mark_runtime_stale: bool = True) -> "PwnWorkspace":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(".pwncraft 文件根节点必须是对象")
        defaults = _workspace_defaults()
        values = {key: _clone_json(payload.get(key, default)) for key, default in defaults.items()}
        workspace = cls(**values)
        raw_variables = payload.get("variables")
        if isinstance(raw_variables, Mapping):
            for name, raw in raw_variables.items():
                if isinstance(raw, Mapping):
                    workspace.variables[str(name)] = WorkspaceVariable.from_dict(raw, fallback_name=str(name))
        if mark_runtime_stale:
            workspace.mark_runtime_stale()
        return workspace

    def _touch(self) -> None:
        self.project["updated_at"] = _now()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_value(value: object) -> object:
    if isinstance(value, TypedAddress):
        return value.to_dict()
    if isinstance(value, WorkspaceVariable):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _clone_json(value: object) -> object:
    if isinstance(value, dict):
        return {key: _clone_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone_json(item) for item in value]
    return value


def _workspace_defaults() -> dict[str, object]:
    return {
        "project": {},
        "target": {},
        "binary": {},
        "symbols": {},
        "runtime": {},
        "libraries": {},
        "gadgets": {"discovered": [], "pinned": [], "semantic_index": {}},
        "syscalls": {"architecture_table": {}, "seccomp_policy": {}},
        "leaks": [],
        "heap": {},
        "stack": {},
        "exploit": {"variables": {}, "stages": [], "chains": [], "primitives": [], "goals": []},
        "notes": [],
    }


Workspace = PwnWorkspace
