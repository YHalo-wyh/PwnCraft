"""Rule-driven strategy planner (VNext.4 front half).

The planner only combines proven facts: each strategy lists what it requires
(node ids), what is still missing, and the evidence it stands on.  Status is
``ready`` (all facts proven), ``unknown`` (needs runtime/experiment evidence
that cannot be derived statically) or ``blocked`` (a required fact is absent).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .facts import TargetFacts
from .graph import (CONFIDENCE_CONDITIONAL, CONFIDENCE_PROVEN, CONFIDENCE_UNKNOWN,
                    PrimitiveGraph)

STATUS_READY = "ready"
STATUS_UNKNOWN = "unknown"
STATUS_BLOCKED = "blocked"

_STATUS_RANK = {STATUS_READY: 0, STATUS_UNKNOWN: 1, STATUS_BLOCKED: 2}

# ``missing`` 的数量不能代表路线质量：一个 speculative 候选往往只写了
# 一个占位缺口，却比已有完整泄漏链少不了多少字段。固定优先级保证输出
# 在不同探测结果/候选插入顺序下仍然稳定，也让 CLI/UI 的 best 路线可解释。
_STRATEGY_PRIORITY = {
    "ret2win": 10,
    "ret2plt": 20,
    "ret2libc": 30,
    "canary-leak-ret2libc": 35,
    "ret2csu-libc": 40,
    "fmt_write": 50,
    "orw": 60,
    "srop": 70,
    "heap": 80,
}


@dataclass(frozen=True)
class ExploitStrategy:
    id: str
    name: str
    status: str
    requires: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    renderer: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "status": self.status,
                "requires": list(self.requires), "missing": list(self.missing),
                "evidence": list(self.evidence), "steps": list(self.steps),
                "renderer": self.renderer}


def _evidence(graph: PrimitiveGraph, *node_ids: str) -> tuple[str, ...]:
    lines: list[str] = []
    for node_id in node_ids:
        node = graph.node(node_id)
        if node is not None:
            lines.extend(node.evidence or (node.detail,))
    return tuple(lines)


def _hijack_state(graph: PrimitiveGraph) -> str:
    node = graph.node("primitive:control_flow_hijack")
    if node is None:
        return CONFIDENCE_UNKNOWN
    return node.confidence


def _win_nodes(graph: PrimitiveGraph) -> list[str]:
    return [item.id for item in graph.nodes if item.id.startswith("primitive:win_function:")]


def plan_strategies(
    facts: TargetFacts,
    graph: PrimitiveGraph,
    *,
    libc_symbols: Mapping[str, int] | None = None,
) -> list[ExploitStrategy]:
    strategies: list[ExploitStrategy] = []
    hijack = _hijack_state(graph)
    pie = facts.is_pie()
    nx = str(facts.security.get("NX") or "UNKNOWN").upper() == "ON"
    hijack_missing = ("控制流劫持偏移未证明（需要崩溃/调试证据）",) if hijack != CONFIDENCE_PROVEN else ()
    canary_missing = ("Canary 已开启但没有泄漏与回填事实",) \
        if str(facts.security.get("CANARY") or "").upper() == "ON" else ()
    pie_missing = ("PIE 已开启但无基址泄漏事实",) if pie else ()
    # x86-64：直接返回进函数需要 16 字节栈对齐，落一次裸 ret（由反汇编证明）
    align_missing = () if (facts.bits != 64 or graph.proven("gadget:ret")) else \
        ("x86-64 对齐用 ret gadget 未从反汇编证明",)
    align_step = ("先落一次 ret（x86-64 16 字节栈对齐）",) if facts.bits == 64 else ()

    wins = _win_nodes(graph)
    shell = graph.node("primitive:shell_string")
    leak = graph.node("primitive:leak")
    syscall = graph.node("primitive:syscall")
    rax = graph.node("gadget:rax")

    # 1) ret2win：程序内已有「以命令为参数」的调用点
    if wins:
        missing = list(hijack_missing) + list(pie_missing) + list(canary_missing) + list(align_missing)
        strategies.append(ExploitStrategy(
            id="ret2win", name="ret2win（跳过程序内现成调用点）",
            status=STATUS_READY if not missing else STATUS_BLOCKED,
            requires=("primitive:win_function:0", "primitive:control_flow_hijack"),
            missing=tuple(missing), evidence=_evidence(graph, wins[0], "primitive:control_flow_hijack"),
            steps=("填充到保存返回地址的偏移",) + align_step + (
                "覆盖返回地址为程序内调用点", "该调用点自带命令参数，无需额外 ROP"),
            renderer="ret2win"))

    # 2) ret2plt：system@plt + /bin/sh + 溢出
    if "system" in facts.plt:
        missing = [] if shell else ["未找到壳字符串（/bin/sh、/bin/bash、/bin/cat）"]
        missing += list(hijack_missing) + list(pie_missing) + list(canary_missing) + list(align_missing)
        if not graph.proven("gadget:rdi") and facts.bits == 64:
            missing.append("pop rdi 控制 gadget 未从 gadget shelf 证明")
        strategies.append(ExploitStrategy(
            id="ret2plt", name="ret2plt（system@plt）",
            status=STATUS_READY if not missing else STATUS_BLOCKED,
            requires=("import:system", "primitive:shell_string", "primitive:control_flow_hijack"),
            missing=tuple(missing),
            evidence=_evidence(graph, "import:system", "primitive:shell_string"),
            steps=("填充到返回地址偏移",) + align_step + ("pop rdi; ret", "参数 = 壳字符串地址",
                   f"call system@plt = 0x{facts.plt['system'].address:x}"),
            renderer="ret2plt"))

    # 3) ret2libc：泄漏 + libc 偏移
    if leak is not None:
        missing = list(hijack_missing) + list(pie_missing) + list(canary_missing) + list(align_missing)
        missing.append("两阶段 GOT 泄漏与重新进入输入点尚未由渲染器实现")
        if not libc_symbols:
            missing.append("libc 文件未提供或符号未解析（system/puts/str_bin_sh）")
        if not graph.proven("gadget:rdi") and facts.bits == 64:
            missing.append("pop rdi 控制 gadget 未从 gadget shelf 证明")
        strategies.append(ExploitStrategy(
            id="ret2libc", name="ret2libc（GOT 泄漏 → libc 基址 → system）",
            status=STATUS_READY if not missing else STATUS_BLOCKED,
            requires=("primitive:leak", "primitive:control_flow_hijack", "primitive:libc_offsets"),
            missing=tuple(missing), evidence=_evidence(graph, "primitive:leak"),
            steps=("泄漏 puts@got → libc base", "再次触发溢出",
                   "ret2libc：pop rdi + binsh@libc + system@libc"),
            renderer="ret2libc"))
        # 变体链：Canary 题先走泄漏/回显，再回到同一输入点；即使尚未
        # 证明完整偏移，也把“先泄漏 canary 再 ret2libc”作为独立候选，
        # 便于自动验证器逐条尝试，而不是过早收敛到单一链。
        if str(facts.security.get("CANARY") or "").upper() == "ON":
            strategies.append(ExploitStrategy(
                id="canary-leak-ret2libc",
                name="Canary 泄漏 → ret2libc（两阶段）",
                status=STATUS_BLOCKED,
                requires=("primitive:leak", "primitive:control_flow_hijack", "primitive:libc_offsets"),
                missing=tuple(list(hijack_missing) + ["Canary 泄漏原语未证明", "第二阶段输入点未证明",
                                                     "两阶段 EXP 尚未实现"]),
                evidence=_evidence(graph, "primitive:leak"),
                steps=("第一阶段构造回显泄漏 canary/PIE", "恢复栈布局并重新进入输入点",
                       "第二阶段 ret2libc"), renderer="ret2libc"))
        # ret2csu 不是“缺少 pop rdi”时的通用兜底：没有两段 CSU gadget
        # 的具体地址就无法构造链，继续展示它只会污染 best 选择。gadget
        # shelf 可用 ``csu_pop/csu_call``（或 ``__libc_csu_init_*``）提供事实。
        csu_pop = graph.proven("gadget:csu_pop", "gadget:csu_call") or \
            graph.proven("gadget:__libc_csu_init_pop", "gadget:__libc_csu_init_call")
        if csu_pop:
            strategies.append(ExploitStrategy(
                id="ret2csu-libc", name="ret2csu → ret2libc（三参数调用）",
                status=STATUS_BLOCKED,
                requires=("primitive:leak", "primitive:control_flow_hijack", "primitive:libc_offsets",
                          "gadget:csu_pop", "gadget:csu_call"),
                missing=tuple(list(hijack_missing) +
                              ([] if libc_symbols else ["libc 文件未提供或符号未解析"]) +
                              ["ret2csu 链渲染器尚未实现"]),
                evidence=_evidence(graph, "primitive:leak", "gadget:csu_pop", "gadget:csu_call"),
                steps=("ret2csu 调用 puts/read 完成泄漏或写入", "回到输入点",
                       "使用 libc system('/bin/sh')"), renderer="ret2libc"))

    # 4) ORW：seccomp 场景，需运行时确认
    if syscall is not None:
        plts = [name for name in ("open", "read", "write") if name in facts.plt]
        missing = list(hijack_missing)
        if len(plts) < 3:
            missing.append(f"open/read/write PLT 不齐（现有 {', '.join(plts) or '无'}）")
        strategies.append(ExploitStrategy(
            id="orw", name="ORW（open/read/write 直读）",
            status=STATUS_UNKNOWN if not missing else STATUS_BLOCKED,
            requires=("primitive:syscall", "primitive:input"),
            missing=tuple(missing) + ("seccomp 规则需运行时确认（无法静态证明）",),
            evidence=_evidence(graph, "primitive:syscall"),
            steps=("确认 seccomp 允许 open/read/write", "布置 ORW ROP 链",
                   "读取 flag 并写回 stdout"),
            renderer="orw"))

    # 5) SROP：syscall + rax 控制
    if syscall is not None:
        missing = list(hijack_missing)
        if rax is None or rax.confidence != CONFIDENCE_PROVEN:
            missing.append("rax 控制 gadget 未证明（sigreturn 需要）")
        strategies.append(ExploitStrategy(
            id="srop", name="SROP（sigreturn 帧）",
            status=STATUS_BLOCKED,
            requires=("primitive:syscall", "gadget:rax", "primitive:control_flow_hijack"),
            missing=tuple(missing) + ("SROP 执行环境与帧返回链尚未验证",), evidence=_evidence(graph, "primitive:syscall"),
            steps=("构造 SigreturnFrame(execve) ", "syscall; ret 触发 rt_sigreturn",
                   "帧内寄存器完成 execve('/bin/sh')"),
            renderer="srop"))

    # 6) 格式化字符串：探针证明（primitive:fmt_controlled）→ ready；否则假设
    fmt_proven = graph.node("primitive:fmt_controlled")
    if fmt_proven is not None:
        strategies.append(ExploitStrategy(
            id="fmt_write", name="格式化字符串写入（%n·探针已证明可控）",
            status=STATUS_BLOCKED,
            requires=("primitive:fmt_controlled", "primitive:input"),
            missing=("格式串参数偏移、写入目标与目标值尚未证明",), evidence=fmt_proven.evidence,
            steps=("fmt 偏移定位（Format 页 / %p 序列）", "确定目标地址与写入值",
                   "按 %hn/%n 分解写入"), renderer="fmt"))
    else:
        fmt = graph.node("hypothesis:format_string")
        if fmt is not None:
            strategies.append(ExploitStrategy(
                id="fmt_write", name="格式化字符串写入（%n）",
                status=STATUS_UNKNOWN,
                requires=("hypothesis:format_string", "primitive:input"),
                missing=("格式串是否受输入控制未证明（需探针实验：%p 回显）",),
                evidence=fmt.evidence, steps=("定位格式串偏移", "确定目标地址与写入值",
                                              "按 %hn/%n 分解写入"),
                renderer="fmt"))

    # 7) 堆域：只有拿到生命周期证据才进入候选
    heap = graph.node("primitive:heap_lifecycle")
    if heap is not None:
        strategies.append(ExploitStrategy(
            id="heap", name="堆利用（生命周期 → 元数据/指针改写）",
            status=STATUS_UNKNOWN,
            requires=("primitive:heap_lifecycle",),
            missing=("需要 heapviz canonical ops / glibc profile 才能裁剪路径",),
            evidence=heap.evidence,
            steps=("由行为证据确定 UAF/溢出点", "按 glibc 版本选 tcache/FSOP 路径",
                   "生成堆操作序列并重放验证"),
            renderer="heap"))

    strategies.sort(key=lambda item: _STATUS_RANK.get(item.status, 3))
    return strategies


def best_strategy(strategies: Sequence[ExploitStrategy]) -> ExploitStrategy | None:
    ranked = sorted(
        strategies,
        key=lambda item: (_STATUS_RANK.get(item.status, 3),
                          _STRATEGY_PRIORITY.get(item.id, 999), len(item.missing)),
    )
    return ranked[0] if ranked else None
