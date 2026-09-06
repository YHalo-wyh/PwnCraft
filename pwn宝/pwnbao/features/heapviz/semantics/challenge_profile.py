from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Mapping

from pwnbao.features.heapviz.operations import HeapOperationKind


def _require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} 必须是 JSON object")
    return value


def _require_list(value: object, label: str) -> list[object]:
    if not isinstance(value, (list, tuple)):
        raise TypeError(f"{label} 必须是 JSON array")
    return list(value)


def _parse_bool(value: object, label: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    raise TypeError(f"{label} 必须是 boolean")


@dataclass(frozen=True)
class BehaviorEffect:
    """One allocator effect emitted by a challenge helper call."""

    kind: str
    chunk: str = ""
    index: str = ""
    request_size: str = ""
    data: str = ""
    field: str = ""
    value: str = ""
    target: str = ""
    fd_storage: str = ""
    count: int = 1
    note: str = ""
    bind_handle: bool = True
    meta: dict[str, str] = dc_field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> BehaviorEffect:
        payload = _require_mapping(payload, "effect")
        kind = str(payload.get("kind") or "").strip()
        if kind not in {item.value for item in HeapOperationKind}:
            raise ValueError(f"未知 behavior effect kind: {kind or '<empty>'}")
        try:
            count = int(payload.get("count") or 1)
        except (TypeError, ValueError) as error:
            raise ValueError("effect.count 必须是正整数") from error
        if count < 1:
            raise ValueError("effect.count 必须是正整数")
        meta_raw = _require_mapping(payload.get("meta") or {}, "effect.meta")
        bind_handle = _parse_bool(payload.get("bind_handle", True), "effect.bind_handle")
        return cls(
            kind=kind,
            chunk=str(payload.get("chunk") or ""),
            index=str(payload.get("index") or ""),
            request_size=str(payload.get("request_size") or payload.get("size") or ""),
            data=str(payload.get("data") or ""),
            field=str(payload.get("field") or ""),
            value=str(payload.get("value") or ""),
            target=str(payload.get("target") or ""),
            fd_storage=str(payload.get("fd_storage") or ""),
            count=count,
            note=str(payload.get("note") or ""),
            bind_handle=bind_handle,
            meta={str(key): str(value) for key, value in meta_raw.items()},
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "chunk": self.chunk,
            "index": self.index,
            "request_size": self.request_size,
            "data": self.data,
            "field": self.field,
            "value": self.value,
            "target": self.target,
            "fd_storage": self.fd_storage,
            "count": self.count,
            "note": self.note,
            "bind_handle": self.bind_handle,
            "meta": dict(self.meta),
        }


@dataclass(frozen=True)
class ChallengeCallBehavior:
    function: str
    parameters: tuple[str, ...] = ()
    effects: tuple[BehaviorEffect, ...] = ()
    defaults: dict[str, str] = dc_field(default_factory=dict)
    receiver: str = ""
    evidence: str = "manual challenge behavior profile"

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> ChallengeCallBehavior:
        payload = _require_mapping(payload, "helper")
        function = str(payload.get("function") or "").strip()
        if not function or not function.isidentifier():
            raise ValueError(f"helper.function 必须是 Python 函数名: {function or '<empty>'}")
        parameters = tuple(
            str(item).strip()
            for item in _require_list(payload.get("parameters") or [], "helper.parameters")
        )
        if any(not item.isidentifier() for item in parameters):
            raise ValueError(f"helper.parameters 包含无效参数名: {parameters!r}")
        if len(parameters) != len(set(parameters)):
            raise ValueError(f"helper.parameters 不允许重复: {parameters!r}")
        effects_raw = _require_list(payload.get("effects") or [], "helper.effects")
        defaults_raw = _require_mapping(payload.get("defaults") or {}, "helper.defaults")
        return cls(
            function=function,
            parameters=parameters,
            effects=tuple(
                BehaviorEffect.from_dict(_require_mapping(item, f"helper.effects[{index}]"))
                for index, item in enumerate(effects_raw)
            ),
            defaults={str(key): str(value) for key, value in defaults_raw.items()},
            receiver=str(payload.get("receiver") or ""),
            evidence=str(payload.get("evidence") or "manual challenge behavior profile"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "function": self.function,
            "receiver": self.receiver,
            "parameters": list(self.parameters),
            "defaults": dict(self.defaults),
            "effects": [item.to_dict() for item in self.effects],
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ChallengeBehaviorProfile:
    name: str = ""
    helpers: tuple[ChallengeCallBehavior, ...] = ()
    version: int = 1

    def match(self, function: str, receiver: str = "") -> ChallengeCallBehavior | None:
        for helper in self.helpers:
            if helper.function != function:
                continue
            if helper.receiver and helper.receiver != receiver:
                continue
            return helper
        return None

    @classmethod
    def from_dict(cls, payload: Mapping[str, object] | None) -> ChallengeBehaviorProfile:
        raw = _require_mapping({} if payload is None else payload, "behavior profile")
        helpers_raw = _require_list(raw.get("helpers") or [], "behavior profile.helpers")
        helpers = tuple(
            ChallengeCallBehavior.from_dict(_require_mapping(item, f"behavior profile.helpers[{index}]"))
            for index, item in enumerate(helpers_raw)
        )
        keys = [(helper.receiver, helper.function) for helper in helpers]
        if len(keys) != len(set(keys)):
            raise ValueError("behavior profile.helpers 不允许重复 receiver/function")
        return cls(
            name=str(raw.get("name") or ""),
            helpers=helpers,
            version=max(1, int(raw.get("version") or 1)),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "name": self.name,
            "helpers": [item.to_dict() for item in self.helpers],
        }
