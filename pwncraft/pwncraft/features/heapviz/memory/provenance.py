from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ProvenanceKind(str, Enum):
    OBSERVED = "observed"
    USER_OBSERVED = "user_observed"
    USER_CONFIRMED = "user_confirmed"
    CALIBRATED = "calibrated"
    DERIVED = "derived"
    INFERRED = "inferred"
    ASSUMED = "assumed"
    UNKNOWN = "unknown"

    # ---- VNext.3.1A-completion: 七值语义来源 (owner 修订)。
    # 细分动机: 复盘时必须能区分「debugger 真读到的」「用户手工断言的」
    # 「识别器推导的」—— 粗粒度 evidence 无法回答结论从哪来。
    # 旧成员保留 (序列化兼容), 新成员只增不改。
    DERIVED_EXP = "derived_exp"                       # EXP 数据流推导
    DERIVED_TARGET = "derived_target"                 # 目标程序行为推导
    DERIVED_ALLOCATOR = "derived_allocator"           # allocator 模拟推导
    OBSERVED_RUNTIME = "observed_runtime"             # GDB 运行时真读 (contract 预留)
    USER_CONFIRMED_CORRECTION = "user_confirmed_correction"  # 用户断言「真实状态如此」
    MANUAL_ASSUMPTION = "manual_assumption"           # 用户假设推演 (非真值)


class WriteKind(str, Enum):
    """How a physical byte span got its current value.

    ``CROSS_CHUNK_OVERWRITE`` is the only kind that may paint the span with
    the cross-write colour: the current final writer of the span is a
    different logical object than the current owner.
    """

    NORMAL_WRITE = "normal_write"
    CROSS_CHUNK_OVERWRITE = "cross_chunk_overwrite"
    ALLOCATOR_WRITE = "allocator_write"
    USER_OBSERVED = "user_observed"
    CALIBRATED = "calibrated"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class MemoryProvenance:
    kind: ProvenanceKind = ProvenanceKind.UNKNOWN
    operation_id: str = ""
    source_line: int = 0
    source_expression: str = ""
    payload_offset: int | None = None
    writer: str = ""
    note: str = ""
    writer_object_id: str = ""
    write_kind: WriteKind = WriteKind.UNKNOWN
    owner_at_write: str = ""
    target_field: str = ""
    target_field_offset: int = 0

    @classmethod
    def derived(
        cls,
        operation_id: str,
        *,
        source_expression: str = "",
        payload_offset: int | None = None,
        writer: str = "",
        note: str = "",
        writer_object_id: str = "",
        write_kind: WriteKind = WriteKind.NORMAL_WRITE,
        owner_at_write: str = "",
        target_field: str = "",
        target_field_offset: int = 0,
    ) -> MemoryProvenance:
        return cls(
            ProvenanceKind.DERIVED,
            operation_id,
            0,
            source_expression,
            payload_offset,
            writer,
            note,
            writer_object_id,
            write_kind,
            owner_at_write,
            target_field,
            target_field_offset,
        )

    @classmethod
    def manual_assumption(
        cls,
        operation_id: str,
        *,
        source_expression: str = "",
        writer: str = "user",
        note: str = "",
        writer_object_id: str = "",
        write_kind: WriteKind = WriteKind.USER_OBSERVED,
        owner_at_write: str = "",
        target_field: str = "",
        target_field_offset: int = 0,
    ) -> MemoryProvenance:
        """MANUAL_ASSUMPTION: 用户利用假设推演 —— 可驱动 hypothetical
        simulation, 但不是目标真实状态; 禁止升级为 DERIVED_*。"""
        return cls(
            ProvenanceKind.MANUAL_ASSUMPTION,
            operation_id,
            0,
            source_expression,
            None,
            writer,
            note,
            writer_object_id,
            write_kind,
            owner_at_write,
            target_field,
            target_field_offset,
        )

    @classmethod
    def user_confirmed_correction(
        cls,
        operation_id: str,
        *,
        source_expression: str = "",
        writer: str = "user",
        note: str = "",
        writer_object_id: str = "",
        write_kind: WriteKind = WriteKind.USER_OBSERVED,
        owner_at_write: str = "",
        target_field: str = "",
        target_field_offset: int = 0,
    ) -> MemoryProvenance:
        """USER_CONFIRMED_CORRECTION: 用户断言「真实状态如此」(可与训练
        闭环衔接, 与 MANUAL_ASSUMPTION 是不同证据等级)。"""
        return cls(
            ProvenanceKind.USER_CONFIRMED_CORRECTION,
            operation_id,
            0,
            source_expression,
            None,
            writer,
            note,
            writer_object_id,
            write_kind,
            owner_at_write,
            target_field,
            target_field_offset,
        )

    @classmethod
    def user_observed(
        cls,
        operation_id: str,
        *,
        source_expression: str = "",
        writer: str = "user",
        note: str = "",
        writer_object_id: str = "",
        write_kind: WriteKind = WriteKind.USER_OBSERVED,
        owner_at_write: str = "",
        target_field: str = "",
        target_field_offset: int = 0,
    ) -> MemoryProvenance:
        return cls(
            ProvenanceKind.USER_OBSERVED,
            operation_id,
            0,
            source_expression,
            None,
            writer,
            note,
            writer_object_id,
            write_kind,
            owner_at_write,
            target_field,
            target_field_offset,
        )
