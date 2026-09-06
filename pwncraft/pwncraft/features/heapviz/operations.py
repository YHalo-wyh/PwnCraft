from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from enum import Enum


class HeapOperationKind(Enum):
    ALLOC = "alloc"
    FREE = "free"
    EDIT = "edit"
    SHOW = "show"
    DERIVE_VALUE = "derive_value"
    COPY = "copy"
    SAFE_LINK_FD = "safe_link_fd"
    OVERFLOW_HEADER = "overflow_header"
    POISON_FD = "poison_fd"
    FAKE_CHUNK = "fake_chunk"
    UNLINK_PREPARE = "unlink_prepare"
    CONSOLIDATE = "consolidate"
    MALLOC_TO_TARGET = "malloc_to_target"
    LEAK_MAIN_ARENA = "leak_main_arena"
    STDOUT_ENVIRON_LEAK = "stdout_environ_leak"
    SETCONTEXT_ROP = "setcontext_rop"
    FILL_TCACHE = "fill_tcache"
    DRAIN_TCACHE = "drain_tcache"
    RESIZE_PHYSICAL = "resize_physical"
    NOTE = "note"


class HeapOperationLayer(Enum):
    PROGRAM = "program"
    CORRUPTION = "corruption"
    INTENT = "intent"



@dataclass(frozen=True)
class HeapOperation:
    op_id: str
    kind: HeapOperationKind
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
    meta: dict[str, str] = dc_field(default_factory=dict)

    @property
    def layer(self) -> HeapOperationLayer:
        if self.kind in {
            HeapOperationKind.ALLOC, HeapOperationKind.FREE, HeapOperationKind.EDIT,
            HeapOperationKind.SHOW, HeapOperationKind.DERIVE_VALUE, HeapOperationKind.COPY, HeapOperationKind.FILL_TCACHE,
            HeapOperationKind.DRAIN_TCACHE,
        }:
            return HeapOperationLayer.PROGRAM
        if self.kind in {
            HeapOperationKind.SAFE_LINK_FD, HeapOperationKind.OVERFLOW_HEADER,
            HeapOperationKind.POISON_FD, HeapOperationKind.FAKE_CHUNK,
            HeapOperationKind.UNLINK_PREPARE,
        }:
            return HeapOperationLayer.CORRUPTION
        return HeapOperationLayer.INTENT

    def title(self) -> str:
        if self.kind == HeapOperationKind.ALLOC:
            return f"{self.op_id} alloc({self.chunk}, {self.request_size})"
        if self.kind == HeapOperationKind.FREE:
            return f"{self.op_id} free({self.chunk or self.index})"
        if self.kind == HeapOperationKind.EDIT:
            return f"{self.op_id} edit({self.chunk or self.index})"
        if self.kind == HeapOperationKind.SHOW:
            return f"{self.op_id} show({self.chunk or self.index})"
        if self.kind == HeapOperationKind.DERIVE_VALUE:
            return f"{self.op_id} derive({self.meta.get('result_var') or self.chunk or 'value'})"
        if self.kind == HeapOperationKind.COPY:
            return f"{self.op_id} copy({self.target} -> {self.chunk or self.index}, {self.request_size})"
        if self.kind == HeapOperationKind.SAFE_LINK_FD:
            return f"{self.op_id} safe-link fd({self.chunk or self.index})"
        if self.kind == HeapOperationKind.OVERFLOW_HEADER:
            return f"{self.op_id} overflow header({self.chunk})"
        if self.kind == HeapOperationKind.POISON_FD:
            return f"{self.op_id} poison fd({self.chunk or self.index} -> {self.target})"
        if self.kind == HeapOperationKind.FAKE_CHUNK:
            return f"{self.op_id} fake chunk({self.chunk or self.target})"
        if self.kind == HeapOperationKind.UNLINK_PREPARE:
            return f"{self.op_id} unlink prepare({self.chunk or self.index})"
        if self.kind == HeapOperationKind.CONSOLIDATE:
            return f"{self.op_id} consolidate fastbin"
        if self.kind == HeapOperationKind.MALLOC_TO_TARGET:
            return f"{self.op_id} malloc to target({self.target})"
        if self.kind == HeapOperationKind.LEAK_MAIN_ARENA:
            return f"{self.op_id} leak main_arena({self.chunk or self.index})"
        if self.kind == HeapOperationKind.STDOUT_ENVIRON_LEAK:
            return f"{self.op_id} stdout -> environ leak"
        if self.kind == HeapOperationKind.SETCONTEXT_ROP:
            return f"{self.op_id} setcontext ROP({self.target or self.chunk})"
        if self.kind == HeapOperationKind.FILL_TCACHE:
            return f"{self.op_id} fill tcache[{self.request_size}]"
        if self.kind == HeapOperationKind.DRAIN_TCACHE:
            return f"{self.op_id} drain tcache[{self.request_size}]"
        if self.kind == HeapOperationKind.RESIZE_PHYSICAL:
            edge = self.meta.get("edge") or "bottom"
            delta = self.meta.get("delta") or "0"
            return f"{self.op_id} resize {self.chunk or self.index} {edge} {delta}"
        return f"{self.op_id} note"

    def to_dict(self) -> dict[str, object]:
        return {
            "op_id": self.op_id,
            "kind": self.kind.value,
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
            "meta": dict(self.meta),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "HeapOperation":
        return cls(
            op_id=str(payload.get("op_id") or ""),
            kind=HeapOperationKind(str(payload.get("kind") or "note")),
            chunk=str(payload.get("chunk") or ""),
            index=str(payload.get("index") or ""),
            request_size=str(payload.get("request_size") or ""),
            data=str(payload.get("data") or ""),
            field=str(payload.get("field") or ""),
            value=str(payload.get("value") or ""),
            target=str(payload.get("target") or ""),
            fd_storage=str(payload.get("fd_storage") or ""),
            count=int(payload.get("count") or 1),
            note=str(payload.get("note") or ""),
            meta={str(k): str(v) for k, v in dict(payload.get("meta") or {}).items()},
        )
