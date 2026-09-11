"""Primitive graph (VNext.3.1#9): evidence-carrying nodes/edges over target facts.

Every node states where it came from (provenance) and how strong it is
(confidence): ``proven`` = read from bytes/relocations/runtime observation,
``conditional`` = a review signal that needs confirmation (e.g. the AWDP audit
length finding), ``unknown`` = a prerequisite we could not derive yet.  The
planner consumes the graph; it never re-derives addresses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .facts import EXEC_IMPORTS, INPUT_IMPORTS, LEAK_IMPORTS, TargetFacts

PROVENANCE_DERIVED = "DERIVED"
PROVENANCE_OBSERVED = "OBSERVED"
PROVENANCE_UNKNOWN = "UNKNOWN"

CONFIDENCE_PROVEN = "proven"
CONFIDENCE_CONDITIONAL = "conditional"
CONFIDENCE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class PrimitiveNode:
    id: str
    kind: str
    detail: str
    evidence: tuple[str, ...] = ()
    provenance: str = PROVENANCE_DERIVED
    confidence: str = CONFIDENCE_PROVEN

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "detail": self.detail,
                "evidence": list(self.evidence), "provenance": self.provenance,
                "confidence": self.confidence}


@dataclass(frozen=True)
class PrimitiveEdge:
    source: str
    target: str
    kind: str

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target, "kind": self.kind}


@dataclass
class PrimitiveGraph:
    nodes: list[PrimitiveNode] = field(default_factory=list)
    edges: list[PrimitiveEdge] = field(default_factory=list)

    def add(self, node: PrimitiveNode) -> None:
        if not self.has(node.id):
            self.nodes.append(node)

    def link(self, source: str, target: str, kind: str) -> None:
        self.edges.append(PrimitiveEdge(source, target, kind))

    def node(self, node_id: str) -> PrimitiveNode | None:
        return next((item for item in self.nodes if item.id == node_id), None)

    def has(self, node_id: str) -> bool:
        return any(item.id == node_id for item in self.nodes)

    def proven(self, *node_ids: str) -> bool:
        for node_id in node_ids:
            item = self.node(node_id)
            if item is None or item.confidence != CONFIDENCE_PROVEN:
                return False
        return True

    def to_dict(self) -> dict:
        return {"nodes": [item.to_dict() for item in self.nodes],
                "edges": [item.to_dict() for item in self.edges]}


def _plt_evidence(facts: TargetFacts, names: Sequence[str]) -> tuple[str, ...]:
    return tuple(f"{name}@plt=0x{facts.plt[name].address:x}" for name in names if name in facts.plt)


def build_primitive_graph(
    facts: TargetFacts,
    *,
    patch_findings: Sequence[Mapping[str, object]] = (),
    stack_truth: Mapping[str, object] | None = None,
    gadgets: Mapping[str, object] | None = None,
    heap_behavior: Mapping[str, object] | None = None,
    libc_symbols: Mapping[str, int] | None = None,
) -> PrimitiveGraph:
    graph = PrimitiveGraph()

    # --- 目标保护事实（策略门禁要用） ------------------------------------
    for key in ("PIE", "NX", "CANARY", "RELRO", "FORTIFY"):
        value = str(facts.security.get(key) or "UNKNOWN").upper()
        graph.add(PrimitiveNode(
            id=f"mitigation:{key}", kind="mitigation", detail=f"{key}={value}",
            evidence=(f"ELF 解析：{key}={value}",), confidence=CONFIDENCE_PROVEN))

    # --- 输入面（漏洞入口） ---------------------------------------------
    inputs = [name for name in INPUT_IMPORTS if name in facts.plt]
    if inputs:
        graph.add(PrimitiveNode(
            id="primitive:input", kind="input_surface",
            detail=f"可写入通道：{', '.join(inputs)}",
            evidence=_plt_evidence(facts, inputs)))
        for name in inputs:
            graph.link("primitive:input", f"import:{name}", "provides")

    length_findings = [item for item in patch_findings
                       if str(item.get("category") or "") == "input_length"]
    if length_findings:
        first = length_findings[0]
        graph.add(PrimitiveNode(
            id="hypothesis:overflow", kind="memory_corruption",
            detail=f"长度过大读入（{first.get('title') or first.get('id')}）",
            evidence=tuple(str(item) for item in (first.get("evidence") or [])[:4])
            + (f"扫描项：{first.get('id')}",),
            provenance=PROVENANCE_DERIVED, confidence=CONFIDENCE_CONDITIONAL))
        graph.link("primitive:input", "hypothesis:overflow", "may_corrupt")

    # --- 控制流劫持证据（运行时观察优先） --------------------------------
    offset = None
    if isinstance(stack_truth, Mapping):
        raw = stack_truth.get("offset") or stack_truth.get("stack_offset")
        if raw is not None:
            try:
                offset = int(str(raw), 0)
            except (TypeError, ValueError):
                offset = None
    if offset is not None:
        graph.add(PrimitiveNode(
            id="primitive:control_flow_hijack", kind="control_flow",
            detail=f"保存返回地址偏移 0x{offset:x}（运行时观测）",
            evidence=(str(stack_truth),), provenance=PROVENANCE_OBSERVED,
            confidence=CONFIDENCE_PROVEN))
    else:
        graph.add(PrimitiveNode(
            id="primitive:control_flow_hijack", kind="control_flow",
            detail="控制流劫持偏移未观测到（需要崩溃/调试证据）",
            evidence=("stack_truth=missing",), provenance=PROVENANCE_UNKNOWN,
            confidence=CONFIDENCE_UNKNOWN))
    if graph.has("hypothesis:overflow"):
        graph.link("hypothesis:overflow", "primitive:control_flow_hijack", "may_enable")

    # --- 命令执行面 ------------------------------------------------------
    exec_names = [name for name in EXEC_IMPORTS if name in facts.plt]
    if exec_names:
        graph.add(PrimitiveNode(
            id="primitive:exec_command", kind="command_execution",
            detail=f"可调用命令执行函数：{', '.join(exec_names)}",
            evidence=_plt_evidence(facts, exec_names)))
    if "system" in facts.plt:
        graph.add(PrimitiveNode(
            id="import:system", kind="import", detail=f"system@plt=0x{facts.plt['system'].address:x}",
            evidence=(f"PLT stub 0x{facts.plt['system'].address:x}",)))

    shell = next(((text, address) for text, address in facts.strings.items()
                  if text in ("/bin/sh", "/bin/bash", "/bin/cat")), None)
    if shell is not None:
        graph.add(PrimitiveNode(
            id="primitive:shell_string", kind="data",
            detail=f"{shell[0]} @ 0x{shell[1]:x}",
            evidence=(f"节内容扫描：{shell[0]} @ 0x{shell[1]:x}",)))

    for index, candidate in enumerate(facts.win_functions):
        graph.add(PrimitiveNode(
            id=f"primitive:win_function:{index}", kind="callable",
            detail=f"{candidate['function']} 调用 {candidate['callee']}"
                   f"（参数 0x{int(candidate['argument_address']):x}）",
            evidence=(f"0x{int(candidate['call_address']):x}: call {candidate['callee']}",
                      f"参数地址 0x{int(candidate['argument_address']):x}"))
        )
        graph.link(f"primitive:win_function:{index}", "primitive:exec_command", "calls")

    # --- 泄漏面 ----------------------------------------------------------
    leak_imports = [name for name in LEAK_IMPORTS if name in facts.plt]
    got_targets = [name for name in (set(LEAK_IMPORTS) | {"read", "strlen", "atoi", "printf"})
                   if name in facts.got]
    if leak_imports and got_targets:
        graph.add(PrimitiveNode(
            id="primitive:leak", kind="information_leak",
            detail=f"可泄漏 GOT 项：{', '.join(sorted(got_targets))}",
            evidence=_plt_evidence(facts, leak_imports)
            + tuple(f"{name}@got=0x{facts.got[name].address:x}" for name in sorted(got_targets))))
        if libc_symbols:
            graph.add(PrimitiveNode(
                id="primitive:libc_offsets", kind="libc",
                detail="libc 符号已解析：" + ", ".join(sorted(libc_symbols)[:6]),
                evidence=tuple(f"{name}=0x{value:x}" for name, value in sorted(libc_symbols.items())[:8])))

    # --- 系统调用 / gadget 面 -------------------------------------------
    if facts.syscalls:
        graph.add(PrimitiveNode(
            id="primitive:syscall", kind="syscall",
            detail=f"{len(facts.syscalls)} 处 syscall 指令",
            evidence=tuple(f"syscall @ 0x{address:x}" for address in facts.syscalls[:4])))
    if facts.ret_gadget():
        graph.add(PrimitiveNode(
            id="gadget:ret", kind="gadget",
            detail=f"裸 ret @ 0x{facts.ret_gadget():x}（x86-64 栈对齐用）",
            evidence=(f"0x{facts.ret_gadget():x}: ret",)))
    for role, value in dict(gadgets or {}).items():
        graph.add(PrimitiveNode(
            id=f"gadget:{role}", kind="gadget", detail=f"{role} = {value}",
            evidence=(f"gadget shelf: {role}={value}",)))
    if graph.has("primitive:syscall") and not graph.has("gadget:rax"):
        graph.add(PrimitiveNode(
            id="gadget:rax", kind="gadget", detail="rax 控制 gadget 未从 gadget shelf 证明",
            evidence=("gadget shelf: missing",), provenance=PROVENANCE_UNKNOWN,
            confidence=CONFIDENCE_UNKNOWN))

    # --- 格式化字符串（审计复核项） --------------------------------------
    format_findings = [item for item in patch_findings
                       if str(item.get("category") or "") == "format_review"]
    if format_findings:
        graph.add(PrimitiveNode(
            id="hypothesis:format_string", kind="format_string",
            detail="存在格式化输出调用（格式串是否可控未证明）",
            evidence=tuple(str(item.get("id")) for item in format_findings[:4]),
            confidence=CONFIDENCE_CONDITIONAL))
        graph.link("primitive:input", "hypothesis:format_string", "may_control")

    # --- 堆生命周期（来自 BinaryIR/行为证据；缺省不建） -------------------
    if isinstance(heap_behavior, Mapping) and heap_behavior.get("actions"):
        graph.add(PrimitiveNode(
            id="primitive:heap_lifecycle", kind="heap",
            detail=f"堆行为证据 {len(list(heap_behavior['actions']))} 条",
            evidence=tuple(str(item) for item in list(heap_behavior["actions"])[:6]),
            provenance=PROVENANCE_OBSERVED))

    # --- 缺口显式化 ------------------------------------------------------
    missing: list[str] = []
    if not graph.has("primitive:control_flow_hijack") or \
            (graph.node("primitive:control_flow_hijack") or PrimitiveNode("", "", "")).confidence == CONFIDENCE_UNKNOWN:
        missing.append("control_flow_offset")
    if not exec_names and not facts.win_functions:
        missing.append("exec_sink")
    if not leak_imports:
        missing.append("leak_sink")
    if not facts.syscalls:
        missing.append("syscall_site")
    if missing:
        graph.add(PrimitiveNode(
            id="unknown:prerequisites", kind="gap",
            detail="静态事实缺口：" + ", ".join(missing),
            evidence=tuple(f"missing:{item}" for item in missing),
            provenance=PROVENANCE_UNKNOWN, confidence=CONFIDENCE_UNKNOWN))
    return graph
