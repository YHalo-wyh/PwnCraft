"""Strict provider contract for IDA/IDACLI semantic evidence snapshots.

The provider does not parse names into vulnerability conclusions. It accepts
only explicit, address-anchored semantic records exported by an analysis
backend and preserves provenance for downstream BinaryIR/audit consumers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any

SCHEMA_VERSION = "pwncraft-binary-semantic-1.0"
_ALLOWED_KINDS = {
    "CALL",
    "STORE",
    "POST_FREE_NULL_STORE",
    "CMP_BOUNDS",
    "TABLE_ACCESS",
    "READ_STDIN",
    "WRITE_STDOUT",
    "CALL_INDIRECT",
    "CONTROL_TRANSFER",
}
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _address(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not an address")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = int(value.strip(), 0)
    else:
        raise ValueError("address must be int or numeric string")
    if result < 0:
        raise ValueError("address must be non-negative")
    return result


@dataclass(frozen=True)
class BinarySemanticEvidence:
    evidence_id: str
    kind: str
    function_address: int
    address: int
    backend: str
    statement: str
    operands: dict[str, Any]
    provenance: str
    confidence: float = 1.0
    source_span: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BinarySemanticSnapshot:
    schema_version: str
    provider: str
    binary_sha256: str
    records: tuple[BinarySemanticEvidence, ...]
    degraded: bool = False
    degrade_notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "binary_sha256": self.binary_sha256,
            "records": [record.to_dict() for record in self.records],
            "degraded": self.degraded,
            "degrade_notes": list(self.degrade_notes),
        }


def load_binary_semantic_snapshot(payload: dict[str, Any]) -> BinarySemanticSnapshot:
    """Validate and normalize one offline semantic-evidence snapshot."""
    if not isinstance(payload, dict):
        raise ValueError("semantic snapshot must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported semantic snapshot schema")
    provider = str(payload.get("provider") or "").strip()
    if not provider:
        raise ValueError("semantic provider identity is required")
    binary_sha256 = str(payload.get("binary_sha256") or "").strip()
    if not _SHA256_RE.fullmatch(binary_sha256):
        raise ValueError("binary_sha256 must be an exact 64-hex digest")

    raw_records = payload.get("records")
    if not isinstance(raw_records, list):
        raise ValueError("semantic records must be a list")

    records: list[BinarySemanticEvidence] = []
    seen: set[str] = set()
    for raw in raw_records:
        if not isinstance(raw, dict):
            raise ValueError("semantic record must be an object")
        evidence_id = str(raw.get("evidence_id") or "").strip()
        if not evidence_id or evidence_id in seen:
            raise ValueError("semantic evidence ids must be unique and non-empty")
        seen.add(evidence_id)
        kind = str(raw.get("kind") or "").strip()
        if kind not in _ALLOWED_KINDS:
            raise ValueError(f"unsupported semantic evidence kind: {kind!r}")
        backend = str(raw.get("backend") or "").strip()
        provenance = str(raw.get("provenance") or "").strip()
        if not backend or not provenance:
            raise ValueError("backend and provenance are required")
        confidence = float(raw.get("confidence", 1.0))
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be within 0..1")
        operands = raw.get("operands") or {}
        if not isinstance(operands, dict):
            raise ValueError("operands must be an object")
        source_span = raw.get("source_span")
        if source_span is not None and not isinstance(source_span, dict):
            raise ValueError("source_span must be an object when present")
        records.append(BinarySemanticEvidence(
            evidence_id=evidence_id,
            kind=kind,
            function_address=_address(raw.get("function_address")),
            address=_address(raw.get("address")),
            backend=backend,
            statement=str(raw.get("statement") or ""),
            operands=dict(operands),
            provenance=provenance,
            confidence=confidence,
            source_span=dict(source_span) if source_span is not None else None,
        ))

    notes = payload.get("degrade_notes") or []
    if not isinstance(notes, list):
        raise ValueError("degrade_notes must be a list")
    return BinarySemanticSnapshot(
        schema_version=SCHEMA_VERSION,
        provider=provider,
        binary_sha256=binary_sha256.lower(),
        records=tuple(records),
        degraded=bool(payload.get("degraded", False)),
        degrade_notes=tuple(str(note) for note in notes),
    )


def evidence_for_function(
    snapshot: BinarySemanticSnapshot,
    function_address: int | str,
) -> list[dict[str, Any]]:
    """Return only exact address-matched evidence for one function."""
    address = _address(function_address)
    return [record.to_dict() for record in snapshot.records if record.function_address == address]


def project_semantic_evidence(snapshot: BinarySemanticSnapshot) -> list[dict[str, Any]]:
    """Project provider records into BinaryIR-compatible evidence dictionaries."""
    projected = []
    for record in snapshot.records:
        projected.append({
            "evidence_id": record.evidence_id,
            "kind": record.kind,
            "function_address": f"{record.function_address:#x}",
            "address": f"{record.address:#x}",
            "backend": record.backend,
            "statement": record.statement,
            "operands": dict(record.operands),
            "provenance": record.provenance,
            "confidence": record.confidence,
            "source_span": dict(record.source_span) if record.source_span is not None else None,
            "binary_sha256": snapshot.binary_sha256,
            "provider": snapshot.provider,
        })
    return projected
