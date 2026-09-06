from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable

from pwnbao.features.heapviz.constraints import ConstraintEngine, ConstraintResult, EditRequest, ValidationStatus
from pwnbao.features.heapviz.contracts import HelperContractResolver, lower_source_calls
from pwnbao.features.heapviz.corrections.model import (
    AllocatorProfilePatch,
    CorrectionPatch,
    HelperContractPatch,
    LayoutPatch,
    ObservedMemoryPatch,
    PatchStatus,
    StructuralViewPatch,
)
from pwnbao.features.heapviz.memory import MemoryProvenance, PhysicalMemory, PhysicalMemorySnapshot, WriteKind
from pwnbao.features.heapviz.models import AllocatorConfig


@dataclass(frozen=True)
class ReplayPlan:
    start_checkpoint: int
    affected_operation_ids: tuple[str, ...] = ()
    relower_contract_ids: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class CorrectionOutcome:
    patch: CorrectionPatch
    result: ConstraintResult
    replay: ReplayPlan | None = None
    memory_changes: tuple[object, ...] = ()
    canonical_operations: tuple[object, ...] = ()


@dataclass(frozen=True)
class _MemoryTransaction:
    patch: CorrectionPatch
    before: PhysicalMemorySnapshot
    after: PhysicalMemorySnapshot
    replay: ReplayPlan


class CorrectionEngine:
    def __init__(self, config: AllocatorConfig | None = None) -> None:
        self.config = config or AllocatorConfig()
        self.constraints = ConstraintEngine(self.config)
        self._patches: list[CorrectionPatch] = []
        self._memory_undo: list[_MemoryTransaction] = []
        self._memory_redo: list[_MemoryTransaction] = []

    @property
    def patches(self) -> tuple[CorrectionPatch, ...]:
        return tuple(self._patches)

    def preview_observed_memory_patch(
        self,
        patch: ObservedMemoryPatch,
        *,
        memory: PhysicalMemory,
    ) -> ConstraintResult:
        """Validate exactly the same request that ``apply`` will commit."""
        length = len(patch.data) if patch.data is not None else patch.length
        request_value: int | bytes | str = patch.data if patch.data is not None else patch.symbolic
        if patch.data is not None and patch.field in {"size", "raw_size", "chunk_size", "fd", "next", "bk", "prev_size"}:
            request_value = int.from_bytes(patch.data, "little")
        request = EditRequest(
            patch.field,
            patch.address,
            request_value,
            length,
            patch.object_id,
            decoded_pointer=patch.decoded_pointer,
        )
        return self.constraints.validate(request, memory)

    def apply(
        self,
        patch: CorrectionPatch,
        *,
        memory: PhysicalMemory,
        source: str = "",
        replay_callback: Callable[[ReplayPlan], None] | None = None,
    ) -> CorrectionOutcome:
        if isinstance(patch, LayoutPatch):
            self._patches.append(patch)
            return CorrectionOutcome(patch, ConstraintResult.valid(layout_only=True), None)
        if isinstance(patch, ObservedMemoryPatch):
            before_memory = memory.snapshot()
            length = len(patch.data) if patch.data is not None else patch.length
            result = self.preview_observed_memory_patch(patch, memory=memory)
            if not result.accepted:
                return CorrectionOutcome(replace(patch, status=PatchStatus.REJECTED), result)
            provenance_kwargs = {}
            if patch.field == "overflow_area":
                start = memory.address(patch.address)
                targets = tuple(
                    item for item in memory.overlaps(start, start.add(length))
                    if item.object_id != patch.object_id
                )
                target = targets[0] if targets else None
                target_offset = max(0, start.offset - target.start.offset) if target is not None else 0
                word = max(1, self.config.bits // 8)
                target_field = (
                    "prev_size" if target_offset < word
                    else "size" if target_offset < word * 2
                    else "user_area"
                )
                provenance_kwargs = {
                    "writer": "canvas-overflow",
                    "writer_object_id": patch.object_id,
                    "write_kind": WriteKind.CROSS_CHUNK_OVERWRITE,
                    "owner_at_write": target.object_id if target is not None else "",
                    "target_field": target_field,
                    "target_field_offset": target_offset % word,
                }
            # VNext.3.1A-completion: 按编辑意图盖 provenance 戳 ——
            # correction = 用户断言真值 (USER_CONFIRMED_CORRECTION);
            # assumption = 利用假设推演 (MANUAL_ASSUMPTION, 非真值)。
            intent = str(getattr(patch, "intent", "") or "correction")
            provenance_factory = (MemoryProvenance.manual_assumption
                                  if intent == "assumption"
                                  else MemoryProvenance.user_confirmed_correction)
            provenance = provenance_factory(
                patch.patch_id,
                source_expression=patch.symbolic or (patch.data.hex() if patch.data is not None else ""),
                note=patch.note,
                **provenance_kwargs,
            )
            if patch.data is not None:
                effective_data = patch.data
                stored = result.normalized.get("stored")
                if patch.decoded_pointer and isinstance(stored, int):
                    effective_data = stored.to_bytes(length, "little")
                changes = memory.write(patch.address, effective_data, provenance)
            else:
                changes = memory.write_symbolic(patch.address, patch.symbolic, patch.length, provenance)
            plan = ReplayPlan(patch.checkpoint + 1, reason="observed memory changed")
            self._patches.append(patch)
            self._memory_undo.append(_MemoryTransaction(patch, before_memory, memory.snapshot(), plan))
            self._memory_redo.clear()
            if replay_callback:
                replay_callback(plan)
            return CorrectionOutcome(patch, result, plan, tuple(changes))
        if isinstance(patch, StructuralViewPatch):
            if patch.size <= 0:
                result = ConstraintResult.invalid("invalid_view_size", "Physical View 大小必须大于 0。", "size")
                return CorrectionOutcome(replace(patch, status=PatchStatus.REJECTED), result)
            try:
                memory.register_object(
                    patch.object_id,
                    patch.address,
                    patch.size,
                    kind=patch.view_kind,
                    label=patch.object_id,
                    provenance="user_confirmed",
                )
            except (TypeError, ValueError) as error:
                result = ConstraintResult.invalid("invalid_view_address", str(error), "address")
                return CorrectionOutcome(replace(patch, status=PatchStatus.REJECTED), result)
            self._patches.append(patch)
            return CorrectionOutcome(patch, ConstraintResult.valid(view_only=True), ReplayPlan(patch.checkpoint + 1, reason="typed view changed"))
        if isinstance(patch, HelperContractPatch):
            if patch.contract is None:
                return CorrectionOutcome(
                    replace(patch, status=PatchStatus.REJECTED),
                    ConstraintResult.invalid("missing_contract", "HelperContractPatch 缺少 contract。"),
                )
            resolution = HelperContractResolver(user_contracts=(patch.contract,)).resolve(source)
            effective = resolution.contract_for(patch.contract.function, patch.contract.receiver)
            if effective is None or effective.status.value == "stale":
                return CorrectionOutcome(
                    replace(patch, status=PatchStatus.STALE),
                    ConstraintResult.unknown("stale_contract", "函数 fingerprint 已变化，旧 Contract 标记 STALE。"),
                )
            operations = lower_source_calls(source, resolution)
            affected = tuple(item.operation_id for item in operations if item.contract_id == effective.contract_id)
            start = min((item.source_binding.line for item in operations if item.contract_id == effective.contract_id), default=patch.checkpoint)
            plan = ReplayPlan(start, affected, (effective.contract_id,), "helper contract changed; re-lower every matching call")
            self._patches.append(patch)
            if replay_callback:
                replay_callback(plan)
            return CorrectionOutcome(patch, ConstraintResult.valid(affected_calls=len(affected)), plan, canonical_operations=operations)
        if isinstance(patch, AllocatorProfilePatch):
            invalid = tuple(key for key in patch.updates if key not in AllocatorConfig.__dataclass_fields__)
            if invalid:
                return CorrectionOutcome(
                    replace(patch, status=PatchStatus.REJECTED),
                    ConstraintResult.invalid("unknown_profile_field", f"未知 allocator profile 字段：{', '.join(invalid)}"),
                )
            self.config = replace(self.config, **patch.updates)
            self.constraints = ConstraintEngine(self.config)
            plan = ReplayPlan(patch.checkpoint, reason="allocator profile changed")
            self._patches.append(patch)
            if replay_callback:
                replay_callback(plan)
            return CorrectionOutcome(patch, ConstraintResult.valid(profile=patch.updates), plan)
        return CorrectionOutcome(
            replace(patch, status=PatchStatus.REJECTED),
            ConstraintResult(ValidationStatus.UNKNOWN),
        )

    def undo_memory(
        self,
        memory: PhysicalMemory,
        replay_callback: Callable[[ReplayPlan], None] | None = None,
    ) -> CorrectionOutcome | None:
        """Undo the latest semantic memory patch at the PhysicalMemory truth source."""
        if not self._memory_undo:
            return None
        transaction = self._memory_undo.pop()
        memory.restore(transaction.before)
        self._memory_redo.append(transaction)
        patch = replace(transaction.patch, status=PatchStatus.UNDONE)
        plan = replace(transaction.replay, reason="undo observed memory patch")
        if replay_callback:
            replay_callback(plan)
        return CorrectionOutcome(patch, ConstraintResult.valid(undone=True), plan)

    def redo_memory(
        self,
        memory: PhysicalMemory,
        replay_callback: Callable[[ReplayPlan], None] | None = None,
    ) -> CorrectionOutcome | None:
        """Redo an undone semantic memory patch without bypassing validation."""
        if not self._memory_redo:
            return None
        transaction = self._memory_redo.pop()
        memory.restore(transaction.after)
        self._memory_undo.append(transaction)
        patch = replace(transaction.patch, status=PatchStatus.ACTIVE)
        plan = replace(transaction.replay, reason="redo observed memory patch")
        if replay_callback:
            replay_callback(plan)
        return CorrectionOutcome(patch, ConstraintResult.valid(redone=True), plan)

    def replay_patches(
        self,
        patches: Iterable[CorrectionPatch],
        *,
        memory: PhysicalMemory,
        source: str = "",
    ) -> tuple[CorrectionOutcome, ...]:
        return tuple(self.apply(item, memory=memory, source=source) for item in patches if item.status is PatchStatus.ACTIVE)
