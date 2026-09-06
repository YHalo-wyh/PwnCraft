#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""共享语义记录词汇表 (阶段 1, VNext M2 公共语义)。

五个记录类型是 heap / stack / fmt 三个领域适配器与比较器的公共语言。
每条记录都带 provenance 与 evidence —— 证据所有权纪律在此生效。

Deterministic-First: 记录只承载事实; 推断在上层且必须引用记录。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# ---- Provenance (与 heapviz ProvenanceKind 对齐的审计层视图) ----
P_OBSERVED = "OBSERVED"
P_OBSERVED_RUNTIME = "OBSERVED_RUNTIME"
P_DERIVED_EXP = "DERIVED_EXP"
P_DERIVED_TARGET = "DERIVED_TARGET"
P_DERIVED_ALLOCATOR = "DERIVED_ALLOCATOR"
P_USER_CONFIRMED_CORRECTION = "USER_CONFIRMED_CORRECTION"
P_MANUAL_ASSUMPTION = "MANUAL_ASSUMPTION"
P_UNKNOWN = "UNKNOWN"


@dataclass
class EvidenceRecord:
    """一条可引用的证据 (owner: Evidence #384 模型)。"""
    evidence_id: str
    kind: str                    # CALL / STORE / RECV_LENGTH / POST_FREE_NULL_STORE / ...
    detail: str
    subject: str = ""            # 证据关于哪个对象/槽位/变量
    address: str = ""            # 二进制地址或源码位置
    source: str = P_DERIVED_EXP  # EXP 数据流 / 目标行为 / 运行时
    confidence: float = 0.9

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValueRecord:
    """ValueIR 的共享视图: 位宽/端序/常量-符号-未知/派生。"""
    kind: str                    # concrete | symbol | expr | range | unknown
    value: int | None = None
    expression: str = ""
    bits: int = 64
    endian: str = "little"
    derivation: str = ""         # 派生链描述 (e.g. "recv(6) -> u64 缺 ljust")
    provenance: str = P_UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EventRecord:
    """一次程序事件: 身份 = 调用位置 + 调用上下文 + 迭代序号。

    禁止用 source_line 单键索引 —— 同一行可有多个调用、循环可多次执行。
    event_id = f"{scope}:L{line}:{action}#{ordinal}"，全局唯一。
    """
    event_id: str
    scope: str                   # 定义所在函数 (或 main)
    line: int
    action: str                  # SEND / SENDLINE / RECV / RECVUNTIL / ALLOC / FREE ...
    ordinal: int = 1             # 同行同动作第几次 (迭代/重复身份)
    callee: str = ""
    args: list[str] = field(default_factory=list)
    parent_event_id: str = ""    # wrapper 展开时的父调用
    source: str = P_DERIVED_EXP

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StateRecord:
    """一个领域状态切片 (堆槽位 / 栈槽 / 寄存器) 的共享描述。"""
    state_id: str
    domain: str                  # heap | stack | fmt
    entries: list[dict] = field(default_factory=list)   # {subject, value/kind, provenance}
    revision: int = 0
    source: str = P_DERIVED_EXP

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiagnosticRecord:
    """比较器/审计器诊断的结构化视图 (早偏差/阻塞层/缺证据/实现边界)。"""
    code: str
    severity: str                # error | warning | suggestion | blocked
    message: str
    layer: str = ""
    line: int = 0
    confidence: float = 1.0
    provenance: str = P_DERIVED_EXP
    evidence: list[dict] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)  # e.g. MANUAL_ASSUMPTION 依赖
    fix_target: str = ""
    suggested_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ordinal_map(events: list[EventRecord]) -> None:
    """为同一 (scope, line, action) 组合分配迭代序号 (原地)。"""
    seen: dict[tuple, int] = {}
    for ev in events:
        key = (ev.scope, ev.line, ev.action)
        seen[key] = seen.get(key, 0) + 1
        ev.ordinal = seen[key]
        ev.event_id = f"{ev.scope}:L{ev.line}:{ev.action}#{ev.ordinal}"
