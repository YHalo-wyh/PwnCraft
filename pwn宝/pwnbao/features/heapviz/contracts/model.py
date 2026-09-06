from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Mapping

from pwnbao.features.heapviz.semantics.canonical_ir import CanonicalOperationKind


class ContractEvidenceSource(IntEnum):
    NAME_CANDIDATE = 10
    SAFE_ALIAS = 20
    WRAPPER = 30
    STRUCTURAL_BODY = 40
    CALLSITE_OUTPUT_FLOW = 45   # VNext.2 M2: 调用点级输出数据流 (EXP-side structural)
    INLINE_ANNOTATION = 50
    IMPORTED_PROFILE = 60
    USER_CONFIRMED = 70


class ContractConfidence(Enum):
    UNKNOWN = "unknown"
    CANDIDATE = "candidate"
    INFERRED = "inferred"
    STRUCTURAL = "structural"
    CONFIRMED = "confirmed"


class ContractScope(Enum):
    CURRENT_CALL = "current_call"
    CURRENT_HELPER = "current_helper"
    CURRENT_CHALLENGE = "current_challenge"
    GLOBAL_TEMPLATE = "global_template"


class ContractStatus(Enum):
    ACTIVE = "active"
    STALE = "stale"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FunctionSignature:
    parameters: tuple[str, ...]
    positional_only: tuple[str, ...] = ()
    keyword_only: tuple[str, ...] = ()
    defaults: tuple[tuple[str, str], ...] = ()
    vararg: str = ""
    kwarg: str = ""

    def default_map(self) -> dict[str, str]:
        return dict(self.defaults)


@dataclass(frozen=True)
class ArgumentBinding:
    role: str
    parameter: str = ""
    expression: str = ""
    position: int = -1
    keyword: str = ""
    fixed: bool = False


@dataclass(frozen=True)
class CanonicalEffect:
    kind: str
    target: str = ""
    expression: str = ""


@dataclass(frozen=True)
class ContractEvidence:
    source: ContractEvidenceSource
    detail: str
    line: int = 0
    score: float = 0.0


@dataclass(frozen=True)
class HelperContract:
    contract_id: str
    function: str
    receiver: str
    operation: CanonicalOperationKind
    signature: FunctionSignature
    roles: dict[str, ArgumentBinding]
    effects: tuple[CanonicalEffect, ...]
    evidence: tuple[ContractEvidence, ...]
    confidence: ContractConfidence
    function_fingerprint: str
    scope: ContractScope = ContractScope.CURRENT_CHALLENGE
    status: ContractStatus = ContractStatus.ACTIVE
    candidate_operation: CanonicalOperationKind = CanonicalOperationKind.UNKNOWN

    @property
    def key(self) -> str:
        return f"{self.receiver}.{self.function}" if self.receiver else self.function

    @property
    def proven(self) -> bool:
        return self.operation is not CanonicalOperationKind.UNKNOWN and self.status is ContractStatus.ACTIVE

    @property
    def strongest_evidence(self) -> ContractEvidenceSource | None:
        return max((item.source for item in self.evidence), default=None)

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_id": self.contract_id,
            "function": self.function,
            "receiver": self.receiver,
            "operation": self.operation.value,
            "candidate_operation": self.candidate_operation.value,
            "signature": {
                "parameters": list(self.signature.parameters),
                "positional_only": list(self.signature.positional_only),
                "keyword_only": list(self.signature.keyword_only),
                "defaults": dict(self.signature.defaults),
                "vararg": self.signature.vararg,
                "kwarg": self.signature.kwarg,
            },
            "roles": {name: binding.__dict__ for name, binding in self.roles.items()},
            "effects": [item.__dict__ for item in self.effects],
            "evidence": [
                {"source": item.source.name, "detail": item.detail, "line": item.line, "score": item.score}
                for item in self.evidence
            ],
            "confidence": self.confidence.value,
            "function_fingerprint": self.function_fingerprint,
            "scope": self.scope.value,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> HelperContract:
        signature_raw = dict(payload.get("signature") or {})
        roles_raw = dict(payload.get("roles") or {})
        return cls(
            contract_id=str(payload.get("contract_id") or ""),
            function=str(payload.get("function") or ""),
            receiver=str(payload.get("receiver") or ""),
            operation=CanonicalOperationKind(str(payload.get("operation") or "unknown")),
            signature=FunctionSignature(
                tuple(str(item) for item in signature_raw.get("parameters", [])),
                tuple(str(item) for item in signature_raw.get("positional_only", [])),
                tuple(str(item) for item in signature_raw.get("keyword_only", [])),
                tuple((str(k), str(v)) for k, v in dict(signature_raw.get("defaults") or {}).items()),
                str(signature_raw.get("vararg") or ""),
                str(signature_raw.get("kwarg") or ""),
            ),
            roles={
                str(name): ArgumentBinding(**{key: value for key, value in dict(raw).items() if key in ArgumentBinding.__dataclass_fields__})
                for name, raw in roles_raw.items()
                if isinstance(raw, Mapping)
            },
            effects=tuple(CanonicalEffect(**dict(item)) for item in list(payload.get("effects") or [])),
            evidence=tuple(
                ContractEvidence(
                    ContractEvidenceSource[str(dict(item).get("source") or "NAME_CANDIDATE")],
                    str(dict(item).get("detail") or ""),
                    int(dict(item).get("line") or 0),
                    float(dict(item).get("score") or 0.0),
                )
                for item in list(payload.get("evidence") or [])
            ),
            confidence=ContractConfidence(str(payload.get("confidence") or "unknown")),
            function_fingerprint=str(payload.get("function_fingerprint") or ""),
            scope=ContractScope(str(payload.get("scope") or "current_challenge")),
            status=ContractStatus(str(payload.get("status") or "active")),
            candidate_operation=CanonicalOperationKind(str(payload.get("candidate_operation") or "unknown")),
        )
