"""Training-case dataset layer (v0.34) — Case Export / Review / Split.

``heap_save`` 是给用户恢复场景的，不承担训练样本格式。这里定义一题的
固定导出结构（generated 层）、外部 Agent 审查条目（review 层）、以及
「同一 challenge family 必须落进同一 split」的分组切分。

三层目录语义（导出方负责落盘到 generated/ review/ accepted/）：
  generated  当前系统输出 —— ``build_case_export`` 的产物
  review     外部 Agent 的判断 —— 独立标签层，绝不直接覆盖 Snapshot
  accepted   经过 proposal → Replay Validator → hard invariants →
             runtime/known-solution evidence → ACCEPTED 的真值样本

engine.recognizer_revision / allocator_profile_revision 必须随样本保存：
三个月后 allocator 或识别器改过，旧样本归谁、还能不能信，全靠这两个
修订号回答。
"""
from __future__ import annotations

import ast
import hashlib
import uuid
from typing import Any, Iterable, Mapping

CASE_SCHEMA_VERSION = "1.0"
REVIEW_SCHEMA_VERSION = "1.0"

# Agent 审查可以报告的问题类型。validator 只对认识的类型做 dry-run。
REVIEW_ISSUE_TYPES = {
    "helper_semantic": "helper 的语义判定错误（alloc/free/edit/show/copy）",
    "helper_argument_role": "helper 参数角色绑定错误（index/size/data…）",
    "offset_derivation": "EDIT offset 推导错误",
    "miscalled_candidate": "某候选调用根本不是堆操作（应忽略）",
}

REVIEW_VERDIFS = ("proposed", "validated", "accepted", "rejected", "retired")

SPLIT_RATIOS = {"train": 0.70, "validation": 0.15, "test": 0.15}


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8")).hexdigest()


def new_case_id(source: str, binary_sha256: str = "") -> str:
    """确定性 case_id：同源码 + 同二进制 = 同一题（重复导出可对齐）。"""
    return "case-" + _sha256_hex(f"{binary_sha256}|{source}")[:20]


def helper_cfg_fingerprint(source: str) -> str:
    """helper CFG 指纹：全部函数定义体的 AST 结构哈希。

    函数名被掩掉 —— 「add」改名叫「buy_goods」但控制流相同的两个 EXP
    是同一家族；body 结构不同（malloc 换 free）则指纹不同。字面量/注释
    本来就不进 AST dump，改菜单文字天然同指纹。split 分组据此防泄漏。
    """
    try:
        tree = ast.parse(str(source or ""))
    except SyntaxError:
        return ""
    shapes: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            anonymous = replace_function_name(node)
            stable = ast.Module(body=[anonymous], type_ignores=[])
            shapes.append(_sha256_hex(ast.dump(stable, include_attributes=False)))
    shapes.sort()
    return _sha256_hex("|".join(shapes)) if shapes else ""


def replace_function_name(node: ast.AST) -> ast.AST:
    """深拷贝函数定义并把名字掩成常量（不改动原树）。"""
    import copy

    clone = copy.deepcopy(node)
    clone.name = "_"
    return clone


def dedup_keys(*, source: str, binary_sha256: str = "", challenge_family: str = "") -> dict[str, str]:
    return {
        "exp_source_sha256": _sha256_hex(source),
        "binary_sha256": str(binary_sha256 or ""),
        "helper_cfg_fingerprint": helper_cfg_fingerprint(source),
        "challenge_family": str(challenge_family or ""),
    }


def build_case_export(
    session: Any,
    *,
    target: Mapping[str, Any] | None = None,
    challenge_family: str = "",
    include_snapshots: bool = True,
) -> dict[str, Any]:
    """把一个 HeapSession 导出为固定 schema 的训练 case（generated 层）。

    ``session`` 需要：source / analysis / helper_contracts / canonical_ops() /
    snapshots / corrections / episodes / recognition_corrections /
    scenario.helper_mappings / allocator_profile()。
    """
    target = dict(target or {})
    analysis = session.analysis
    recognition: dict[str, Any] = {}
    if analysis is not None:
        report = getattr(analysis, "recognition_report", None) or {}
        recognition = {
            **report,
            "bindings": [
                {
                    "source_id": binding.source_id,
                    "line": binding.line,
                    "source_text": binding.source_text,
                    "confidence": binding.confidence,
                    "match_status": binding.match_status,
                    "fingerprint": binding.fingerprint,
                }
                for binding in analysis.bindings
            ],
            "valid": analysis.valid,
            "diagnostics": [
                {
                    "severity": item.severity,
                    "code": item.code,
                    "message": item.message,
                    "line": item.line,
                }
                for item in analysis.diagnostics
            ],
        }
    profile = session.allocator_profile()
    from pwncraft import APP_VERSION

    state = session.state()
    snapshots = state["steps"] if include_snapshots else []
    return {
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": new_case_id(str(session.source), str(target.get("binary_sha256") or "")),
        "target": {
            "binary_sha256": str(target.get("binary_sha256") or ""),
            "libc_sha256": str(target.get("libc_sha256") or ""),
            "ld_sha256": str(target.get("ld_sha256") or ""),
            "arch": str(target.get("arch") or profile.arch),
        },
        "engine": {
            "version": APP_VERSION,
            "recognizer_revision": recognition.get("recognizer_revision", ""),
            "allocator_profile_id": profile.profile_id,
            "allocator_profile_revision": profile.profile_revision,
            "simulation_mode": profile.simulation_mode,
        },
        "input": {
            "exp_source": str(session.source or ""),
            "attachments": list(target.get("attachments") or []),
        },
        "recognition": recognition,
        "helper_contracts": [dict(item) for item in session.helper_contracts],
        "helper_mappings": [dict(item) for item in session.scenario.helper_mappings],
        "learned_rules": [dict(item) for item in session.learned_rules],
        "canonical_ops": state["canonical_ops"],
        "snapshots": snapshots,
        "corrections": [dict(item) for item in session.corrections],
        "learning_episodes": [dict(item) for item in session.episodes],
        "recognition_corrections": [dict(item) for item in getattr(session, "recognition_corrections", [])],
        "dedup": dedup_keys(
            source=str(session.source or ""),
            binary_sha256=str(target.get("binary_sha256") or ""),
            challenge_family=challenge_family,
        ),
    }


# ---------------------------------------------------------------------------
# Case validation（heap_validate_case）


def validate_case(case: Mapping[str, Any]) -> list[str]:
    """结构 + hard invariants 校验。返回 issues 列表；空列表 = 通过。"""
    issues: list[str] = []
    if not isinstance(case, Mapping):
        return ["case 不是 JSON 对象"]
    if str(case.get("schema_version") or "") != CASE_SCHEMA_VERSION:
        issues.append(f"schema_version 必须是 {CASE_SCHEMA_VERSION}，收到 {case.get('schema_version')!r}")
    if not str(case.get("case_id") or ""):
        issues.append("缺少 case_id")
    engine = case.get("engine") or {}
    if not isinstance(engine, Mapping):
        issues.append("engine 不是对象")
    else:
        for key in ("version", "recognizer_revision", "allocator_profile_id", "allocator_profile_revision"):
            if not str(engine.get(key) or ""):
                issues.append(f"engine.{key} 缺失 —— 没有 revision 的样本三个月后无法归因")
    target = case.get("target") or {}
    if not isinstance(target, Mapping) or not str(target.get("arch") or ""):
        issues.append("target.arch 缺失")
    inp = case.get("input") or {}
    if not isinstance(inp, Mapping) or "exp_source" not in inp:
        issues.append("input.exp_source 缺失")
    snapshots = case.get("snapshots")
    if snapshots is not None:
        if not isinstance(snapshots, list):
            issues.append("snapshots 不是数组")
        else:
            steps = [item.get("step") for item in snapshots if isinstance(item, Mapping)]
            if steps != sorted(steps) or len(set(steps)) != len(steps):
                issues.append("snapshots.step 必须单调递增且唯一")
            if case.get("canonical_ops"):
                op_steps = [item.get("step") for item in case["canonical_ops"] if isinstance(item, Mapping)]
                if op_steps and steps and max(op_steps) > max(steps):
                    issues.append("canonical_ops 引用了不存在的 step（超出 snapshots 范围）")
    for key in ("corrections", "learning_episodes"):
        for item in case.get(key) or []:
            checkpoint = (item or {}).get("checkpoint")
            if snapshots and isinstance(checkpoint, int):
                if steps and not (0 <= checkpoint <= max(steps)):
                    issues.append(f"{key} 引用了越界 checkpoint {checkpoint}")
    return issues


# ---------------------------------------------------------------------------
# Review 层（独立标签层，绝不直接覆盖 Snapshot）


def normalize_review(payload: Mapping[str, Any]) -> dict[str, Any]:
    """补全 review 结构；verdict 一律从 proposed 起步，导入不改快照。"""
    raw = dict(payload or {})
    target = dict(raw.get("target") or {})
    review_id = str(raw.get("review_id") or "").strip() or f"R-{uuid.uuid4().hex[:6]}"
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "review_id": review_id,
        "issue_type": str(raw.get("issue_type") or "").strip(),
        "target": {
            "source_line": int(target.get("source_line") or 0),
            "call_id": str(target.get("call_id") or ""),
            "function": str(target.get("function") or ""),
        },
        "before": dict(raw.get("before") or {}),
        "proposed": dict(raw.get("proposed") or {}),
        "confidence": float(raw.get("confidence") or 0.0),
        "evidence": [str(item) for item in list(raw.get("evidence") or [])],
        "verdict": str(raw.get("verdict") or "proposed"),
        "note": str(raw.get("note") or ""),
    }


def validate_review_against_case(review: Mapping[str, Any], case: Mapping[str, Any]) -> list[str]:
    """静态 gate：review 引用的行/调用必须在 case 里真实存在。"""
    issues: list[str] = []
    if str(review.get("issue_type") or "") not in REVIEW_ISSUE_TYPES:
        issues.append(f"未知 issue_type: {review.get('issue_type')!r}（支持：{'/'.join(sorted(REVIEW_ISSUE_TYPES))}）")
    if str(review.get("verdict") or "") not in REVIEW_VERDIFS:
        issues.append(f"非法 verdict: {review.get('verdict')!r}")
    if not dict(review.get("proposed") or {}):
        issues.append("proposed 为空：没有可验证的提议")
    target = dict(review.get("target") or {})
    line = int(target.get("source_line") or 0)
    recognition = dict(case.get("recognition") or {})
    candidates = recognition.get("candidates") or []
    bindings = recognition.get("bindings") or []
    if line:
        known_lines = {int(item.get("line") or 0) for item in candidates}
        known_lines |= {int(item.get("line") or 0) for item in bindings}
        if known_lines and line not in known_lines:
            issues.append(f"target.source_line={line} 不在该 case 的任何候选/绑定里")
    call_id = str(target.get("call_id") or "")
    if call_id:
        op_ids = {str(item.get("op_id") or "") for item in case.get("canonical_ops") or []}
        if op_ids and call_id not in op_ids:
            issues.append(f"target.call_id={call_id} 不在 canonical_ops 里")
    return issues


# ---------------------------------------------------------------------------
# Split 分组（第一天就把 train/validation/test 分开，防家族泄漏）


def family_key(case: Mapping[str, Any]) -> str:
    """同一题的所有变体共享的分组键。

    优先显式 challenge_family；否则 binary_sha256；再否则 helper CFG 指纹
    （把「改菜单文字的 babyheap」与原版聚在一起 —— 它们的 helper 结构
    相同）。最后兜底 exp 源码哈希。
    """
    dedup = dict(case.get("dedup") or {})
    return str(
        dedup.get("challenge_family")
        or dedup.get("binary_sha256")
        or dedup.get("helper_cfg_fingerprint")
        or dedup.get("exp_source_sha256")
        or ""
    )


def assign_splits(
    cases: Iterable[Mapping[str, Any]],
    ratios: Mapping[str, float] | None = None,
    seed: str = "pwncraft-v1",
) -> dict[str, str]:
    """确定性 family 级 70/15/15 切分。

    整个 family 落进同一个 split（babyheap 2018 / 2019 / 博客复制版 /
    改菜单版 → 同一键 → 同侧），杜绝「随机按文件分导致测试集见过近似题」。
    确定性：families 按 sha256(family + seed) 排序后按累计比例切；train
    优先补整（保证极小语料下 train 仍最大），test 永远保留至少一个
    family（当 family 总数 ≥ 2）。
    """
    ratios = {**SPLIT_RATIOS, **(ratios or {})}
    families = sorted({key for key in (family_key(case) for case in cases) if key})
    ordered = sorted(families, key=lambda key: _sha256_hex(f"{seed}|{key}"))
    total = len(ordered)
    if not total:
        return {}

    def cut(count: int) -> int:
        return max(1 if count else 0, round(count))

    n_test = min(cut(total * ratios["test"]), total // 2) if total >= 2 else 0
    n_validation = min(cut(total * ratios["validation"]), total - n_test - 1) if total >= 2 else 0
    n_train = total - n_test - n_validation

    assignment: dict[str, str] = {}
    for index, family in enumerate(ordered):
        if index < n_train:
            assignment[family] = "train"
        elif index < n_train + n_validation:
            assignment[family] = "validation"
        else:
            assignment[family] = "test"
    return assignment
