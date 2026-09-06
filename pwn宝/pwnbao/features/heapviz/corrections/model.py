from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pwnbao.features.heapviz.contracts import ContractScope, HelperContract


class PatchKind(Enum):
    LAYOUT = "layout"
    HELPER_CONTRACT = "helper_contract"
    OBSERVED_MEMORY = "observed_memory"
    STRUCTURAL_VIEW = "structural_view"
    ALLOCATOR_PROFILE = "allocator_profile"


class PatchStatus(Enum):
    ACTIVE = "active"
    STALE = "stale"
    REJECTED = "rejected"
    UNDONE = "undone"


@dataclass(frozen=True)
class CorrectionPatch:
    patch_id: str
    checkpoint: int = 0
    status: PatchStatus = PatchStatus.ACTIVE
    note: str = ""

    @property
    def kind(self) -> PatchKind:
        raise NotImplementedError

    @property
    def semantic(self) -> bool:
        return self.kind is not PatchKind.LAYOUT


@dataclass(frozen=True)
class LayoutPatch(CorrectionPatch):
    object_id: str = ""
    before: dict[str, object] = field(default_factory=dict)
    after: dict[str, object] = field(default_factory=dict)

    @property
    def kind(self) -> PatchKind:
        return PatchKind.LAYOUT


@dataclass(frozen=True)
class HelperContractPatch(CorrectionPatch):
    contract: HelperContract | None = None
    previous_contract: HelperContract | None = None
    scope: ContractScope = ContractScope.CURRENT_CHALLENGE

    @property
    def kind(self) -> PatchKind:
        return PatchKind.HELPER_CONTRACT


@dataclass(frozen=True)
class ObservedMemoryPatch(CorrectionPatch):
    address: str = ""
    data: bytes | None = None
    symbolic: str = ""
    length: int = 0
    field: str = "user_area"
    object_id: str = ""
    decoded_pointer: bool = False
    intent: str = "correction"   # VNext.3.1A-completion: correction|assumption

    @property
    def kind(self) -> PatchKind:
        return PatchKind.OBSERVED_MEMORY


@dataclass(frozen=True)
class StructuralViewPatch(CorrectionPatch):
    object_id: str = ""
    address: str = ""
    size: int = 0
    view_kind: str = "malloc_chunk_candidate"
    evidence_level: str = "candidate"

    @property
    def kind(self) -> PatchKind:
        return PatchKind.STRUCTURAL_VIEW


@dataclass(frozen=True)
class AllocatorProfilePatch(CorrectionPatch):
    updates: dict[str, object] = field(default_factory=dict)
    helper: str = ""

    @property
    def kind(self) -> PatchKind:
        return PatchKind.ALLOCATOR_PROFILE
