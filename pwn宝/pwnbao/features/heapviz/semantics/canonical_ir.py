from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pwnbao.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwnbao.features.heapviz.semantics.values import (
    AbstractValue,
    ConcreteInt,
    LengthExpr,
    UnknownValue,
    byte_length,
    evaluate_value,
    render_value,
)


class CanonicalOperationKind(Enum):
    ALLOC = "alloc"
    EDIT = "edit"
    SHOW = "show"
    DELETE = "delete"
    FREE = "delete"
    COPY = "copy"
    MEMORY_WRITE = "memory_write"
    FIELD_WRITE = "field_write"
    INTENT_ASSERTION = "intent_assertion"
    VALUE = "value"
    UNKNOWN = "unknown"


class SemanticConfidence(Enum):
    CONFIRMED = "confirmed"
    STRUCTURAL = "structural"
    INFERRED = "inferred"
    CANDIDATE = "candidate"
    UNKNOWN = "unknown"
    STALE = "stale"


@dataclass(frozen=True)
class CanonicalSourceBinding:
    source_id: str = ""
    line: int = 0
    start: int = 0
    end: int = 0
    source_text: str = ""
    fingerprint: str = ""


@dataclass(frozen=True)
class CanonicalHeapOperation:
    operation_id: str
    kind: CanonicalOperationKind
    handle: AbstractValue = field(default_factory=lambda: UnknownValue("handle unavailable"))
    menu_request: AbstractValue = field(default_factory=lambda: UnknownValue("menu request unavailable"))
    allocator_request: AbstractValue = field(default_factory=lambda: UnknownValue("allocator request unproven"))
    offset: AbstractValue = field(default_factory=lambda: ConcreteInt(0, "default edit offset"))
    length: AbstractValue = field(default_factory=lambda: UnknownValue("length unavailable"))
    payload: AbstractValue = field(default_factory=lambda: UnknownValue("payload unavailable"))
    target: AbstractValue = field(default_factory=lambda: UnknownValue("target unavailable"))
    source_binding: CanonicalSourceBinding = field(default_factory=CanonicalSourceBinding)
    contract_id: str = ""
    confidence: SemanticConfidence = SemanticConfidence.UNKNOWN
    provenance: tuple[str, ...] = ()
    annotation: str = ""

    @property
    def index(self) -> AbstractValue:
        return self.handle

    @property
    def request_size(self) -> AbstractValue:
        return self.menu_request

    @property
    def allocator_request_size(self) -> AbstractValue:
        return self.allocator_request

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "kind": self.kind.value,
            "handle": render_value(self.handle),
            "menu_request": render_value(self.menu_request),
            "allocator_request": render_value(self.allocator_request),
            "offset": render_value(self.offset),
            "length": render_value(self.length),
            "payload": render_value(self.payload),
            "target": render_value(self.target),
            "source_binding": self.source_binding.__dict__,
            "contract_id": self.contract_id,
            "confidence": self.confidence.value,
            "provenance": list(self.provenance),
            "annotation": self.annotation,
        }


_LEGACY_KIND_MAP = {
    HeapOperationKind.ALLOC: CanonicalOperationKind.ALLOC,
    HeapOperationKind.FREE: CanonicalOperationKind.DELETE,
    HeapOperationKind.EDIT: CanonicalOperationKind.EDIT,
    HeapOperationKind.SHOW: CanonicalOperationKind.SHOW,
    HeapOperationKind.COPY: CanonicalOperationKind.COPY,
    HeapOperationKind.DERIVE_VALUE: CanonicalOperationKind.VALUE,
    HeapOperationKind.OVERFLOW_HEADER: CanonicalOperationKind.MEMORY_WRITE,
    HeapOperationKind.POISON_FD: CanonicalOperationKind.MEMORY_WRITE,
    HeapOperationKind.SAFE_LINK_FD: CanonicalOperationKind.FIELD_WRITE,
    HeapOperationKind.MALLOC_TO_TARGET: CanonicalOperationKind.INTENT_ASSERTION,
}


def canonical_from_legacy(
    operation: HeapOperation,
    source_binding: CanonicalSourceBinding | None = None,
    contract_id: str = "",
) -> CanonicalHeapOperation:
    """Compatibility adapter; v0.12 fields never need to hide in ``meta`` again."""

    kind = _LEGACY_KIND_MAP.get(operation.kind, CanonicalOperationKind.UNKNOWN)
    handle_text = operation.index or operation.chunk
    menu_request = evaluate_value(operation.request_size) if operation.request_size else UnknownValue("menu request absent")
    payload = evaluate_value(operation.data) if operation.data else UnknownValue("payload absent")
    offset_text = operation.meta.get("offset", "0") if operation.kind == HeapOperationKind.EDIT else "0"
    offset = evaluate_value(offset_text)
    declared_length = operation.meta.get("length") or operation.meta.get("write_length")
    if declared_length:
        length: AbstractValue = evaluate_value(declared_length)
    elif operation.kind == HeapOperationKind.EDIT:
        length = byte_length(payload)
        if isinstance(length, UnknownValue) and operation.data:
            length = LengthExpr(f"len({operation.data})", ())
    else:
        length = UnknownValue("length absent")
    allocator_text = operation.meta.get("allocator_request", "")
    allocator_request = evaluate_value(allocator_text) if allocator_text else UnknownValue(
        "menu request is not proof of allocator request",
        operation.request_size,
    )
    confidence_text = operation.meta.get("parse_confidence", "unknown")
    confidence = {
        "confirmed": SemanticConfidence.CONFIRMED,
        "structural": SemanticConfidence.STRUCTURAL,
        "inferred": SemanticConfidence.INFERRED,
        "candidate": SemanticConfidence.CANDIDATE,
        "stale": SemanticConfidence.STALE,
    }.get(confidence_text, SemanticConfidence.UNKNOWN)
    return CanonicalHeapOperation(
        operation.op_id,
        kind,
        handle=evaluate_value(handle_text) if handle_text else UnknownValue("handle absent"),
        menu_request=menu_request,
        allocator_request=allocator_request,
        offset=offset,
        length=length,
        payload=payload,
        target=evaluate_value(operation.target) if operation.target else UnknownValue("target absent"),
        source_binding=source_binding or CanonicalSourceBinding(),
        contract_id=contract_id,
        confidence=confidence,
        provenance=("legacy-adapter",),
        annotation=operation.note,
    )


def legacy_from_canonical(operation: CanonicalHeapOperation) -> HeapOperation:
    reverse = {
        CanonicalOperationKind.ALLOC: HeapOperationKind.ALLOC,
        CanonicalOperationKind.DELETE: HeapOperationKind.FREE,
        CanonicalOperationKind.EDIT: HeapOperationKind.EDIT,
        CanonicalOperationKind.SHOW: HeapOperationKind.SHOW,
        CanonicalOperationKind.COPY: HeapOperationKind.COPY,
        CanonicalOperationKind.VALUE: HeapOperationKind.DERIVE_VALUE,
        CanonicalOperationKind.MEMORY_WRITE: HeapOperationKind.EDIT,
        CanonicalOperationKind.FIELD_WRITE: HeapOperationKind.EDIT,
        CanonicalOperationKind.INTENT_ASSERTION: HeapOperationKind.NOTE,
    }
    meta = {
        "canonical": "true",
        "offset": render_value(operation.offset),
        "length": render_value(operation.length),
        "allocator_request": render_value(operation.allocator_request),
        "contract_id": operation.contract_id,
        "parse_confidence": operation.confidence.value,
    }
    return HeapOperation(
        operation.operation_id,
        reverse.get(operation.kind, HeapOperationKind.NOTE),
        index=render_value(operation.handle),
        request_size=render_value(operation.menu_request),
        data=render_value(operation.payload),
        target=render_value(operation.target),
        note=operation.annotation,
        meta=meta,
    )


def canonicalize_operations(
    operations: tuple[HeapOperation, ...] | list[HeapOperation],
    bindings: tuple[object, ...] | list[object] = (),
) -> tuple[CanonicalHeapOperation, ...]:
    result: list[CanonicalHeapOperation] = []
    for index, operation in enumerate(operations):
        raw = bindings[index] if index < len(bindings) else None
        binding = CanonicalSourceBinding(
            source_id=str(getattr(raw, "source_id", "")),
            line=int(getattr(raw, "line", 0)),
            start=int(getattr(raw, "start", 0)),
            end=int(getattr(raw, "end", 0)),
            source_text=str(getattr(raw, "source_text", "")),
            fingerprint=str(getattr(raw, "fingerprint", "")),
        ) if raw is not None else CanonicalSourceBinding()
        result.append(canonical_from_legacy(operation, binding))
    return tuple(result)
