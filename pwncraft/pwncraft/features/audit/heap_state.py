"""Heap state machine + first rule batch (VNext.3).

The state machine replays the EXP's helper calls against the target's
ChallengeBehaviorProfile semantics and BehaviorFacts, then rules verify the
EXP's assumptions. Core discipline: UNKNOWN ≠ FALSE — an unconfirmed pointer
clearing produces a Suggestion, never an Error.
"""
from __future__ import annotations

import ast

from pwncraft.features.audit.model import (
    Diagnostic, ExploitIR, SourceSpan, PROVENANCE_DERIVED,
    SEVERITY_ERROR, SEVERITY_SUGGESTION, SEVERITY_WARNING,
)
from pwncraft.features.audit.values import SymbolicValue

# VNext.3.1 #7: helper 内联深度护栏 —— wrapper-of-wrapper 展开上限,
# 超深嵌套按 unknown 调用处理 (不猜语义, 不崩溃)。
INLINE_DEPTH_LIMIT = 2

_FREE = "free"
_ALLOC = "alloc"
_EDIT = "edit"
_SHOW = "show"


def helper_semantics(profile: dict) -> dict[str, dict]:
    """Derive per-helper heap semantics from a ChallengeBehaviorProfile dict:
    {helper: {kind: alloc|free|edit|show, index_param, clears_pointer|None}}.

    clears_pointer is None when no BehaviorFact decides it (UNKNOWN).
    """
    semantics: dict[str, dict] = {}
    facts_by_scope: dict[str, list[dict]] = {}
    for fact in (profile.get("behavior_facts") or []):
        scope = str(fact.get("scope") or "")
        facts_by_scope.setdefault(scope.split("@")[0], []).append(fact)

    def _decides_clear(helper: str) -> bool | None:
        for fact in facts_by_scope.get(helper, []):
            kind = fact.get("kind")
            if kind == "CLEAR_POINTER":
                return True
            if kind == "KEEP_DANGLING_POINTER":
                return False
            if kind == "CLEAR_POINTER_NOT_OBSERVED":
                return False if fact.get("backend") == "source-ast" else None
        return None

    for helper in profile.get("helpers") or []:
        name = str(helper.get("function") or "")
        effects = helper.get("effects") or []
        kinds = {str(e.get("kind") or "") for e in effects}
        params = [str(p) for p in (helper.get("parameters") or [])]
        entry: dict = {"kinds": kinds}
        if _FREE in kinds:
            entry["kind"] = _FREE
            entry["index_param"] = params[0] if params else ""
            entry["clears_pointer"] = _decides_clear(name)
            entry["double_free_capable"] = "KEEP_DANGLING_POINTER" in {
                str(f.get("kind")) for f in facts_by_scope.get(name, [])}
        elif _ALLOC in kinds:
            entry["kind"] = _ALLOC
            entry["index_param"] = ""
        elif _EDIT in kinds or _SHOW in kinds:
            entry["kind"] = _EDIT if _EDIT in kinds else _SHOW
            entry["index_param"] = params[0] if params else ""
        else:
            entry["kind"] = "other"
        semantics[name] = entry
    return semantics


class HeapStateMachine:
    """Replays indexed helper calls. v1 tracks concrete integer indices."""

    def __init__(self, semantics: dict[str, dict]):
        self.semantics = semantics
        self.live: dict[int, str] = {}       # index -> alloc helper
        self.freed: dict[int, str] = {}      # index -> free helper
        self.cleared: dict[int, bool] = {}   # index -> pointer cleared?

    def apply(self, call) -> list[tuple[str, int, dict]]:
        """Apply one helper call; returns [(event, index, info), ...]."""
        events: list[tuple[str, int, dict]] = []
        sem = self.semantics.get(call.function)
        if not sem:
            return events
        index = self._index_of(call, sem.get("index_param") or "")
        if index is None:
            return events
        kind = sem.get("kind")
        if kind == _ALLOC:
            self.live[index] = call.function
            self.freed.pop(index, None)
            events.append(("ALLOC", index, {}))
        elif kind == _FREE:
            self.freed[index] = call.function
            self.live.pop(index, None)
            cleared = sem.get("clears_pointer")
            self.cleared[index] = cleared
            events.append(("FREE", index, {"clears_pointer": cleared}))
        elif kind in (_EDIT, _SHOW):
            if index in self.freed:
                events.append((f"{kind.upper()}_AFTER_FREE", index,
                               {"cleared": self.cleared.get(index),
                                "free_helper": self.freed[index]}))
        return events

    @staticmethod
    def _index_of(call, index_param: str) -> int | None:
        if not index_param:
            return None
        params = []
        # helper_calls args are positional; parameter names live in semantics
        # caller mapping is resolved by the rules layer via profile parameters
        return None

    def apply_indexed(self, function: str, args: list[str],
                      parameters: list[str]) -> list[tuple[str, int, dict]]:
        """Index-resolving apply: bind index_param positionally, evaluate ints."""
        sem = self.semantics.get(function)
        if not sem:
            return []
        index_param = sem.get("index_param") or ""
        index = None
        if index_param and index_param in parameters:
            position = parameters.index(index_param)
            if position < len(args):
                # Symbolic Value Domain: only CONCRETE drives exact state
                # transitions; symbolic/expr indices degrade to UNKNOWN events
                value = SymbolicValue.unknown("argument not literal")
                try:
                    literal = ast.literal_eval(args[position])
                    if isinstance(literal, int):
                        value = SymbolicValue.concrete(int(literal))
                except (ValueError, SyntaxError, MemoryError):
                    pass
                index = value.as_int()
        if index is None:
            return []  # symbolic index: no guessed transition (Deterministic-First)
        events: list[tuple[str, int, dict]] = []
        kind = sem.get("kind")
        if kind == _ALLOC:
            self.live[index] = function
            self.freed.pop(index, None)
            self.cleared.pop(index, None)
            events.append(("ALLOC", index, {}))
        elif kind == _FREE:
            self.freed[index] = function
            self.live.pop(index, None)
            cleared = sem.get("clears_pointer")
            self.cleared[index] = cleared
            events.append(("FREE", index, {"clears_pointer": cleared}))
        elif kind in (_EDIT, _SHOW):
            if index in self.freed:
                events.append((f"{kind.upper()}_AFTER_FREE", index,
                               {"cleared": self.cleared.get(index),
                                "free_helper": self.freed[index]}))
        return events


def run_rules(ir: ExploitIR, *, bits: int = 64, pie: bool = False,
              profile: dict | None = None) -> list[Diagnostic]:
    """First deterministic rule batch (v1: the highest-value rules)."""
    diagnostics: list[Diagnostic] = []
    semantics = helper_semantics(profile or {})
    parameters_by_helper = {
        str(h.get("function")): [str(p) for p in (h.get("parameters") or [])]
        for h in (profile or {}).get("helpers", [])
    }

    # ---- leak packing rules
    for op in ir.unpacks:
        width = 8 if op.fn == "u64" else 4
        length = getattr(op, "meta_recv_length", None)
        unknown = getattr(op, "meta_recv_unknown", False)
        if "ljust" in op.arg:
            continue
        if length is not None and length < width:
            diagnostics.append(Diagnostic(
                code=f"EXP_LEAK_001" if width == 8 else "EXP_LEAK_002",
                severity=SEVERITY_ERROR,
                confidence=0.99,
                message=f"{op.fn}() 输入可能不足 {width} 字节: {op.arg} 来自 "
                        f"recv({length})，当前表达式没有 0x00 padding。",
                line=op.line,
                evidence=[{"kind": "RECV_LENGTH", "detail": f"{op.arg} <- recv({length})"},
                          {"kind": "UNPACK", "detail": f"{op.fn}({op.arg}) 需要 {width} 字节"}],
                suggested_fix=f"{op.fn}({op.arg}.ljust({width}, b'\\x00'))",
                fix_target=f"{op.fn}({op.arg})",
                span=SourceSpan(line=op.line).to_dict(),
                provenance=PROVENANCE_DERIVED,
                impact="leak 解析失败或直接抛异常。"))
        elif unknown or length is None:
            if "ljust" not in op.arg and op.fn == "u64" and not op.arg.startswith("u64"):
                diagnostics.append(Diagnostic(
                    code="EXP_LEAK_003",
                    severity=SEVERITY_SUGGESTION,
                    confidence=0.55,
                    message=f"{op.fn}({op.arg}) 的输入长度未知（recvline/流式），"
                            "不足 8 字节时解析会错位。",
                    line=op.line,
                    evidence=[{"kind": "RECV_LENGTH", "detail": "unknown length"}],
                    suggested_fix=f"{op.fn}({op.arg}.ljust(8, b'\\x00'))",
                    impact="libc leak 可能错位；确认定界后再解析。"))

    # ---- arch packing rules
    for op in ir.packs:
        hints_address = any(h in op.arg.lower() for h in
                            ("addr", "system", "hook", "gadget", "leak",
                             "ptr", "base"))
        if bits == 64 and op.fn == "p32" and hints_address:
            diagnostics.append(Diagnostic(
                code="EXP_ARCH_001",
                severity=SEVERITY_ERROR,
                confidence=0.9,
                message=f"目标程序为 amd64 (64-bit)，但 {op.arg} 使用 p32() 打包，"
                        "极可能发生地址截断。",
                line=op.line,
                evidence=[{"kind": "BINARY_BITS", "detail": "64"},
                          {"kind": "PACK", "detail": f"p32({op.arg})"}],
                suggested_fix=f"p64({op.arg})",
                fix_target=f"p32({op.arg})",
                span=SourceSpan(line=op.line).to_dict(),
                provenance=PROVENANCE_DERIVED,
                impact="写入的地址被截断为 4 字节，利用几乎必然失败。"))
        elif bits == 32 and op.fn == "p64" and hints_address:
            diagnostics.append(Diagnostic(
                code="EXP_ARCH_002",
                severity=SEVERITY_ERROR,
                confidence=0.9,
                message=f"目标程序为 32-bit，但 {op.arg} 使用 p64() 打包。",
                line=op.line,
                evidence=[{"kind": "BINARY_BITS", "detail": "32"}],
                suggested_fix=f"p32({op.arg})",
                impact="写入 8 字节会破坏相邻内存。"))

    # ---- PIE hardcode rule
    if pie:
        for hc in ir.hardcodes:
            diagnostics.append(Diagnostic(
                code="EXP_PIE_001",
                severity=SEVERITY_SUGGESTION,
                confidence=0.8,
                message=f"{hc.var} = {hc.value:#x} 是固定绝对地址，"
                        "而目标启用了 PIE —— 每次运行基址不同。",
                line=hc.line,
                evidence=[{"kind": "PIE", "detail": "enabled"},
                          {"kind": "HARDCODE", "detail": f"{hc.var}={hc.value:#x}"}],
                suggested_fix=f"{hc.var} = leak - offset  # 由泄露推导",
                impact="非 PIE 场景下该地址才有效；PIE 下需先泄露基址。"))

    # ---- M2 公共值流: 调用点接收结果的实际使用 (EXP_LEAK_004)
    for var in ir.var_recv_length:
        used = any(var in (op.arg or "") for op in ir.unpacks)
        used = used or any(var in (op.arg or "") for op in ir.packs)
        used = used or any(
            var in (i.value or "") or var in (i.wait_for or "")
            for i in ir.interactions if i.value or i.wait_for)
        if not used:
            diagnostics.append(Diagnostic(
                code="EXP_LEAK_004",
                severity=SEVERITY_SUGGESTION,
                confidence=0.5,
                message=f"recv 结果 {var} 接收后从未被使用 —— 泄露链可能缺失"
                        "（漏写 u64 解析或后续计算）。",
                line=0,
                evidence=[{"kind": "RECV_LENGTH",
                           "detail": f"{var} <- recv({ir.var_recv_length[var]})"}],
                suggested_fix=f"# 使用 {var}: {var}.ljust(8, b'\x00') 后 u64 解析",
                impact="泄露数据被丢弃, 利用链断裂。"))

    # ---- heap lifecycle rules (EXP ↔ BehaviorProfile cross validation)
    if profile:
        machine = HeapStateMachine(semantics)
        for call in ir.helper_calls:
            params = parameters_by_helper.get(call.function) or []
            for event, index, info in machine.apply_indexed(
                    call.function, call.args, params):
                if event == "EDIT_AFTER_FREE" or event == "SHOW_AFTER_FREE":
                    cleared = info.get("cleared")
                    helper = info.get("free_helper")
                    if cleared is True:
                        # pass through the intermediate semantic-evidence
                        # chain (e.g. POST_FREE_NULL_STORE) from the fact
                        chain = [f for f in (profile or {}).get("behavior_facts", [])
                                 if str(f.get("kind")) == "CLEAR_POINTER"
                                 and str(f.get("scope", "")).split("@")[0] == helper]
                        evidence = [{"kind": "FREE",
                                     "detail": f"{helper} 释放 chunks[{index}]"}]
                        for fact in chain:
                            evidence.extend(fact.get("evidence") or [])
                        diagnostics.append(Diagnostic(
                            code="EXP_HEAP_014",
                            severity=SEVERITY_ERROR,
                            confidence=0.9,
                            message=f"你正在 {event.split('_')[0].lower()} 已释放的 "
                                    f"chunk[{index}]，但目标程序在 free 后会清空"
                                    "对应指针 —— UAF 假设不成立。",
                            line=call.line,
                            evidence=evidence,
                            suggested_fix="检查是否存在其他悬空引用 / index alias，"
                                          "或改用不被清空的对象。",
                            impact="edit/show 作用在空指针上，无法构成 UAF。"))
                    elif cleared is None:
                        diagnostics.append(Diagnostic(
                            code="EXP_HEAP_021",
                            severity=SEVERITY_SUGGESTION,
                            confidence=0.61,
                            message=f"当前利用似乎依赖 chunk[{index}] 释放后的悬垂"
                                    "指针，但尚未观察到指针是否被清除的证据。",
                            line=call.line,
                            evidence=[{"kind": "FREE", "detail": f"{helper} 释放 chunks[{index}]"},
                                      {"kind": "CLEAR_POINTER", "detail": "UNKNOWN"}],
                            suggested_fix="确认目标 delete 路径是否清空指针。",
                            impact="若指针被清除，UAF 假设不成立。"))
                elif event == "FREE" and index in ir_free_counts(ir, call, index):
                    pass
    return diagnostics


def ir_free_counts(ir: ExploitIR, call, index: int) -> list:
    """Helper for EXP_HEAP_015 (double free) — v1 defers to M2 dataflow."""
    return []
