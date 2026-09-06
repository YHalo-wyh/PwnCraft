"""Correction Learning Engine (v0.33) — 可验证的本地自主学习.

用户在 Heap 画布上的一次编辑不再是 ``{"old": ..., "new": ...}``，而是带完整
语义上下文的 **CorrectionEpisode**；Correction Intent Resolver 把编辑向上追踪到
调用点实参与 helper 形参绑定，产出三类意图（不猜、可验证、可否决）：

① semantic_contract  语义识别纠错 —— 证据链 = USER_CORRECTION + STATIC_DATAFLOW +
   REQUEST2SIZE_MATCH（例：chunk 0x110 → 用户改 0x90，r2s⁻¹(0x90)=0x80 恰为调用点
   第 1 位实参 ⇒ 「该形参才是 request_size」）。学成 HelperContract
   （confidence=confirmed，resolver 里 USER_CONFIRMED 证据级最高，结构推断永远
   不能覆盖它），随后整题重分析。
② observed_state     物理状态纠错 —— 程序内部写入（如 chunk->size = 0x421）EXP 源码
   不可见：只做 PhysicalMemory 写入 + 后缀重放，影响本题后续状态，
   **不**触碰 helper contract（Analyzer 并没有错）。
③ derivation_rule    推导规则纠错 —— 例：edit 的 payload offset 第一次被用户纠正为 0，
   且 helper 体文本显示数据就是从 user pointer 起点写入 ⇒ 生成
   LearnedRule(target=EDIT.offset, expression=Constant(0),
   evidence=[USER_CORRECTION, STATIC_DATAFLOW_TEXT])，本题该类操作此后自动推导。

置信度阶梯（高→低）：USER_CONFIRMED > CALIBRATED > STRUCTURAL > ALIAS > UNKNOWN。
低置信度永远不能覆盖高置信度。
"""
from __future__ import annotations

import ast
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from pwncraft.features.heapviz.expressions import parse_int_expr

CONFIDENCE_ORDER = {
    "USER_CONFIRMED": 5,
    "CALIBRATED": 4,
    "STRUCTURAL": 3,
    "ALIAS": 2,
    "UNKNOWN": 1,
}

INTENT_SEMANTIC = "semantic_contract"
INTENT_OBSERVED = "observed_state"
INTENT_DERIVED = "derivation_rule"

INTENT_LABELS = {
    INTENT_SEMANTIC: "语义识别纠错（HelperContract）",
    INTENT_OBSERVED: "物理状态纠错（ObservedState）",
    INTENT_DERIVED: "推导规则纠错（LearnedRule）",
}


def _hash(text: str) -> str:
    return hashlib.sha1(str(text or "").encode("utf-8")).hexdigest()[:16]


@dataclass
class CorrectionEpisode:
    """一次画布校正的完整语义上下文（不是 old/new 对）。"""

    correction_id: str
    checkpoint: int
    source_location: int = 0
    source_function: str = ""
    source_operation: str = ""
    source_call_text: str = ""
    field_name: str = ""
    address: str = ""
    before_value: str = ""
    after_value: str = ""
    changed_physical_range: list[int] = field(default_factory=list)
    changed_typed_fields: list[str] = field(default_factory=list)
    analyzer_reasoning: str = ""
    candidates: list[dict[str, Any]] = field(default_factory=list)
    inferred_intent: str = INTENT_OBSERVED
    intent_label: str = INTENT_LABELS[INTENT_OBSERVED]
    confidence: str = "USER_CONFIRMED"
    scope: str = "scene"
    challenge_fingerprint: str = ""
    helper_fingerprint: str = ""
    note: str = ""
    # Correction context v2/v3 —— 「可训练」字段。训练需要的不是
    # 「用户把 0x51 改成 0x91」，而是：在什么上下文下、系统为什么得到 A、
    # 用户为什么改成 B、角色绑定如何翻转。这些字段让一次画布校正成为
    # 自足的监督样本（before/after 必须完整成对）。
    parameter_names: list[str] = field(default_factory=list)
    argument_expressions: list[str] = field(default_factory=list)
    function_fingerprint: str = ""        # helper 定义体 AST 指纹（源码变化即失效）
    callsite_fingerprint: str = ""        # 调用点 AST 指纹（analyzer binding 签发）
    role_candidates_before: list[dict[str, Any]] = field(default_factory=list)  # 识别报告的语义评分
    role_binding_before: dict[str, Any] = field(default_factory=dict)
    role_binding_after: dict[str, Any] = field(default_factory=dict)
    previous_op: dict[str, Any] = field(default_factory=dict)
    next_op: dict[str, Any] = field(default_factory=dict)
    target_fingerprint: str = ""          # 被校正目标（physical_id|address|field）指纹
    allocator_profile: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "correction_id": self.correction_id,
            "checkpoint": self.checkpoint,
            "source_location": self.source_location,
            "source_function": self.source_function,
            "source_operation": self.source_operation,
            "source_call_text": self.source_call_text,
            "field_name": self.field_name,
            "address": self.address,
            "before_value": self.before_value,
            "after_value": self.after_value,
            "changed_physical_range": list(self.changed_physical_range),
            "changed_typed_fields": list(self.changed_typed_fields),
            "analyzer_reasoning": self.analyzer_reasoning,
            "candidates": list(self.candidates),
            "inferred_intent": self.inferred_intent,
            "intent_label": self.intent_label,
            "confidence": self.confidence,
            "scope": self.scope,
            "challenge_fingerprint": self.challenge_fingerprint,
            "helper_fingerprint": self.helper_fingerprint,
            "note": self.note,
            "parameter_names": list(self.parameter_names),
            "argument_expressions": list(self.argument_expressions),
            "function_fingerprint": self.function_fingerprint,
            "callsite_fingerprint": self.callsite_fingerprint,
            "role_candidates_before": [dict(item) for item in self.role_candidates_before],
            "role_binding_before": dict(self.role_binding_before),
            "role_binding_after": dict(self.role_binding_after),
            "previous_op": dict(self.previous_op),
            "next_op": dict(self.next_op),
            "target_fingerprint": self.target_fingerprint,
            "allocator_profile": self.allocator_profile,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CorrectionEpisode":
        raw = dict(payload or {})
        return cls(
            correction_id=str(raw.get("correction_id") or ""),
            checkpoint=int(raw.get("checkpoint") or 0),
            source_location=int(raw.get("source_location") or 0),
            source_function=str(raw.get("source_function") or ""),
            source_operation=str(raw.get("source_operation") or ""),
            source_call_text=str(raw.get("source_call_text") or ""),
            field_name=str(raw.get("field_name") or ""),
            address=str(raw.get("address") or ""),
            before_value=str(raw.get("before_value") or ""),
            after_value=str(raw.get("after_value") or ""),
            changed_physical_range=[int(item) for item in list(raw.get("changed_physical_range") or [])],
            changed_typed_fields=[str(item) for item in list(raw.get("changed_typed_fields") or [])],
            analyzer_reasoning=str(raw.get("analyzer_reasoning") or ""),
            candidates=[dict(item) for item in list(raw.get("candidates") or []) if isinstance(item, Mapping)],
            inferred_intent=str(raw.get("inferred_intent") or INTENT_OBSERVED),
            intent_label=str(raw.get("intent_label") or INTENT_LABELS[INTENT_OBSERVED]),
            confidence=str(raw.get("confidence") or "USER_CONFIRMED"),
            scope=str(raw.get("scope") or "scene"),
            challenge_fingerprint=str(raw.get("challenge_fingerprint") or ""),
            helper_fingerprint=str(raw.get("helper_fingerprint") or ""),
            note=str(raw.get("note") or ""),
            parameter_names=[str(item) for item in list(raw.get("parameter_names") or [])],
            argument_expressions=[str(item) for item in list(raw.get("argument_expressions") or [])],
            function_fingerprint=str(raw.get("function_fingerprint") or ""),
            callsite_fingerprint=str(raw.get("callsite_fingerprint") or ""),
            role_candidates_before=[
                dict(item) for item in list(raw.get("role_candidates_before") or []) if isinstance(item, Mapping)
            ],
            role_binding_before=dict(raw.get("role_binding_before") or raw.get("role_bindings") or {}),
            role_binding_after=dict(raw.get("role_binding_after") or {}),
            previous_op=dict(raw.get("previous_op") or {}),
            next_op=dict(raw.get("next_op") or {}),
            target_fingerprint=str(raw.get("target_fingerprint") or ""),
            allocator_profile=str(raw.get("allocator_profile") or ""),
        )


# ---------------------------------------------------------------------------
# Call-site static dataflow（有界、确定性：AST 解析调用点文本，不执行用户代码）


def parse_call_site(call_text: str) -> dict[str, Any]:
    """从绑定行文本解析 helper 名、位置实参表达式、关键字实参。"""
    result = {"function": "", "args": [], "keywords": {}}
    text = str(call_text or "").strip()
    if not text:
        return result
    node = None
    try:
        wrapped = ast.parse(f"_({text})", mode="eval").body   # Call: _(...)
        inner = wrapped.args[0] if wrapped.args else None
        if isinstance(inner, ast.Call):
            node = inner            # text 是普通调用表达式
        elif isinstance(wrapped.func, ast.Call):
            node = wrapped.func     # 兜底
    except (SyntaxError, ValueError):
        node = None
    if node is None:
        try:
            node = ast.parse(text, mode="eval").body
        except (SyntaxError, ValueError):
            return result
    if not isinstance(node, ast.Call):
        return result
    result["function"] = node.func.id if isinstance(node.func, ast.Name) else ""
    result["args"] = [ast.unparse(arg) for arg in node.args]
    result["keywords"] = {
        str(keyword.arg): ast.unparse(keyword.value)
        for keyword in node.keywords
        if keyword.arg
    }
    return result


def _literal_int(expression: str, variables: Mapping[str, Any]) -> int | None:
    try:
        return parse_int_expr(str(expression), variables)
    except (TypeError, ValueError):
        return None


def helper_def_text(source: str, helper: str, max_lines: int = 60) -> str:
    """截取 ``def helper(...)`` 起的函数体文本（供文本级数据流检查）。"""
    lines = str(source or "").splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.lstrip().startswith(f"def {helper}("):
            start = index
            break
    if start is None:
        return ""
    indent = len(lines[start]) - len(lines[start].lstrip())
    block = [lines[start]]
    for line in lines[start + 1:start + max_lines]:
        if not line.strip():
            block.append(line)
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= indent:
            break
        block.append(line)
    return "\n".join(block)


def helper_signature(source: str, helper: str) -> tuple[list[str], str]:
    """从源码取 helper 的形参名列表 + resolver 同款 AST 指纹（不匹配则契约判 STALE）。

    指纹算法与 ``contracts.resolver.function_fingerprint`` 完全一致：
    sha256(ast.dump(FunctionDef))。
    """
    text = str(source or "")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], ""
    definitions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            definitions.append(node)
    for node in definitions:
        if node.name == helper:
            parameters = [
                item.arg
                for item in (*node.args.posonlyargs, *node.args.args)
                if item.arg not in {"self", "cls"}
            ]
            stable = ast.Module(body=[node], type_ignores=[])
            fingerprint = hashlib.sha256(
                ast.dump(stable, include_attributes=False).encode()
            ).hexdigest()
            return parameters, fingerprint
    return [], ""


def offset_zero_dataflow_confirmed(helper_body: str) -> bool:
    """文本级数据流：helper 体把 data 从 user pointer 起点直接写入。

    有界启发：写入语句出现 data 且没有「+ offset / [1:] 」式的起点偏移。
    这是对 ``write(ptr[idx], data, ...)`` 形态的保守确认——不做执行、不猜。
    """
    body = str(helper_body or "")
    if not body:
        return False
    writes = ("write(", "send(", "sendline(", "sendafter(", "sendlineafter(")
    if not any(token in body for token in writes):
        return False
    if "data" not in body:
        return False
    offset_signs = ("+ 0x", "+0x", "[1:]", "ptr +", "p64(")
    return not any(token in body for token in offset_signs)


# ---------------------------------------------------------------------------
# Intent Resolver


def _candidate(kind: str, title: str, detail: str, evidence: list[str], strength: float) -> dict[str, Any]:
    return {
        "kind": kind,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "strength": round(float(strength), 2),
    }


def build_semantic_contract(
    helper: str,
    call: Mapping[str, Any],
    size_position: int,
    request_value: int,
    source_line: int,
    helper_fingerprint: str,
    parameters: list[str] | None = None,
) -> dict[str, Any]:
    """从调用点实参构造 USER_CONFIRMED HelperContract（dict，resolver 直接可消费）。

    角色映射保守构造：命中 request2size 预像的实参 → size（对应形参名取自函数定义）；
    bytes 类实参 → data；其余整数实参 → index。全部标注在 evidence/detail 里，
    confidence=confirmed 保证后续结构推断不能覆盖。
    """
    args = list(call.get("args") or [])
    parameters = list(parameters or [])
    roles: dict[str, dict[str, Any]] = {}
    for position, expression in enumerate(args):
        value = _literal_int(expression, {})
        if position == size_position:
            role = "size"
        elif value is not None:
            role = "index"
        else:
            role = "data"
        if role in roles:
            continue   # 同角色取首次出现的实参，后位不覆盖
        roles[role] = {
            "role": role,
            "parameter": parameters[position] if position < len(parameters) else "",
            "expression": expression,
            "position": position,
            "keyword": "",
            "fixed": False,
        }
    return {
        "contract_id": f"user-{helper}-{_hash(helper + str(helper_fingerprint))}",
        "function": helper,
        "receiver": "",
        "operation": "alloc",
        "candidate_operation": "alloc",
        "signature": {
            "parameters": parameters,
            "positional_only": [],
            "defaults": {},
            "vararg": "",
            "kwarg": "",
        },
        "roles": roles,
        "effects": [],
        "evidence": [
            {
                "source": "USER_CONFIRMED",
                "detail": (
                    f"画布校正：chunk size 与调用点第 {size_position} 位实参 "
                    f"({args[size_position]!r} → request2size={request_value:#x}) 静态数据流匹配"
                ),
                "line": source_line,
                "score": 1.0,
            }
        ],
        "confidence": "confirmed",
        "function_fingerprint": helper_fingerprint,
        "scope": "current_challenge",
        "status": "active",
    }


def resolve_correction_intent(
    *,
    step: int,
    operation: Mapping[str, Any] | None,
    call: Mapping[str, Any],
    source_line: int,
    source_source: str,
    chunk: Mapping[str, Any] | None,
    field_name: str,
    before_value: str,
    after_value: str,
    patch_value_int: int | None,
    variables: Mapping[str, Any],
    helper_body: str,
    intent_hint: str = "",
) -> dict[str, Any]:
    """Correction Intent Resolver：向上追踪 + 证据打分 + 意图分类。

    不黑盒：每条候选带证据链与强度；主意图 = 证据最强者，
    ``intent_hint`` 允许用户显式否决自动判定。
    """
    candidates: list[dict[str, Any]] = []
    helper = str(call.get("function") or "")
    parameters, helper_fingerprint = helper_signature(source_source, helper)
    if not helper_fingerprint:
        helper_fingerprint = _hash(helper_def_text(source_source, helper) or helper)

    # 基线候选：物理状态纠错（无论识别对错，这次写入本身就是 USER_OBSERVED 事实）
    candidates.append(_candidate(
        INTENT_OBSERVED,
        "ObservedState：程序内部写入，仅推进本题状态",
        f"{field_name} 在 checkpoint #{step} 的用户观测写入（{before_value or '?'} → {after_value or '?'}）；"
        "PhysicalMemory.write + 后缀重放，不影响 helper contract。",
        ["USER_OBSERVED"],
        0.4,
    ))

    semantic_contract: dict[str, Any] | None = None
    learned_rule: dict[str, Any] | None = None
    primary = INTENT_OBSERVED
    confidence = "CALIBRATED"
    reasoning = "校正按用户观测写入处理。"

    if field_name in {"size", "raw_size", "chunk_size"} and patch_value_int:
        corrected = int(patch_value_int)
        corrected &= ~0x7 if corrected & 0x7 else corrected
        size_sz = 8
        preimage = corrected - size_sz
        if preimage > 0:
            args = list(call.get("args") or [])
            for position, expression in enumerate(args):
                literal = _literal_int(expression, variables)
                if literal is None:
                    continue
                # r2s(literal) 直接可算：request + 8 再对齐
                aligned = (literal + size_sz + 0xF) & ~0xF
                if aligned == corrected and literal != corrected:
                    candidates.append(_candidate(
                        INTENT_SEMANTIC,
                        f"HelperContract：{helper} 第 {position} 位实参才是 request_size",
                        f"你改出的 chunk size {corrected:#x} = request2size({expression})，"
                        f"与调用点第 {position} 位实参静态匹配 ⇒ 当前 size 角色绑定错了，"
                        f"应绑定到该实参对应形参。",
                        ["USER_CORRECTION", "STATIC_DATAFLOW", "REQUEST2SIZE_MATCH"],
                        0.95,
                    ))
                    semantic_contract = build_semantic_contract(
                        helper, call, position, corrected, source_line, helper_fingerprint,
                        parameters=parameters,
                    )
                    break
        if semantic_contract is None:
            reasoning = (
                "调用点没有任何实参能静态解释该 chunk size：判为程序内部写入"
                "（ObservedState），不修改 Analyzer 的 helper contract —— Analyzer 本身没有识别错。"
            )

    if field_name == "user_area" and operation and str(operation.get("kind")) == "edit":
        if offset_zero_dataflow_confirmed(helper_body):
            learned_rule = {
                "rule_id": f"rule-{uuid.uuid4().hex[:8]}",
                "family": "derivation",
                "target": "EDIT.offset",
                "condition": {"helper": helper, "helper_fingerprint": helper_fingerprint},
                "expression": "0",
                "evidence": ["USER_CORRECTION", "STATIC_DATAFLOW_TEXT"],
                "scope": "scene",
                "enabled": True,
                "confidence": "USER_CONFIRMED",
                "reason": f"{helper} 的 payload 从 user pointer 起点写入（文本级数据流确认），offset 推导为 0",
            }
            candidates.append(_candidate(
                INTENT_DERIVED,
                f"LearnedRule：{helper} 的 EDIT.offset = 0",
                "helper 体文本显示 data 从 user pointer 起点直接写入 ⇒ 本题该 helper 的 edit "
                "offset 自动推导为 0（后续识别优先参考该规则）。",
                ["USER_CORRECTION", "STATIC_DATAFLOW_TEXT"],
                0.85,
            ))

    strongest = max(candidates, key=lambda item: item["strength"])
    if strongest["kind"] != INTENT_OBSERVED:
        primary = strongest["kind"]
        confidence = "USER_CONFIRMED"
        reasoning = strongest["detail"]

    if intent_hint in {INTENT_SEMANTIC, INTENT_OBSERVED, INTENT_DERIVED} and intent_hint != primary:
        # 用户显式否决自动判定（不黑盒）
        primary = intent_hint
        confidence = "USER_CONFIRMED"
        reasoning += "（用户显式指定意图）"

    episode = CorrectionEpisode(
        correction_id=f"corr-{uuid.uuid4().hex[:12]}",
        checkpoint=step,
        source_location=source_line,
        source_function=helper,
        source_operation=(
            f"{(operation or {}).get('op_id', '')}:{(operation or {}).get('kind', '')}"
            if operation else ""
        ),
        source_call_text=str(call.get("__text__") or ""),
        field_name=field_name,
        address="",
        before_value=before_value,
        after_value=after_value,
        analyzer_reasoning=reasoning,
        candidates=candidates,
        inferred_intent=primary,
        intent_label=INTENT_LABELS.get(primary, primary),
        confidence=confidence,
        scope="scene",
        challenge_fingerprint=_hash(source_source),
        helper_fingerprint=helper_fingerprint,
    )
    return {
        "intent": primary,
        "intent_label": INTENT_LABELS.get(primary, primary),
        "confidence": confidence,
        "scope": "scene",
        "candidates": candidates,
        "reasoning": reasoning,
        "helper": helper,
        "helper_fingerprint": helper_fingerprint,
        "episode": episode,
        "helper_contract": semantic_contract if primary == INTENT_SEMANTIC else None,
        "learned_rule": learned_rule if primary == INTENT_DERIVED else None,
    }
