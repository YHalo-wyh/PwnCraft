from __future__ import annotations

from .model import ContractEvidenceSource


EVIDENCE_PRIORITY = (
    ContractEvidenceSource.USER_CONFIRMED,
    ContractEvidenceSource.IMPORTED_PROFILE,
    ContractEvidenceSource.INLINE_ANNOTATION,
    ContractEvidenceSource.STRUCTURAL_BODY,
    ContractEvidenceSource.WRAPPER,
    ContractEvidenceSource.SAFE_ALIAS,
    ContractEvidenceSource.NAME_CANDIDATE,
)
