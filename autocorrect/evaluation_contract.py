#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evaluation contracts (阶段 0.1, M0 验收可信).

每个案例可携带 evaluation_contract.json，声明本次验收的必需材料：
  required_layers     哪些比较层必须实际执行 (缺失 → 整题 INCONCLUSIVE)
  not_applicable      明确不适用的层 (如普通栈题的 BINS/ALLOCATOR)
  required_artifacts  哪些生成物必须存在 (renderer_plan / canvas_invariants ...)
  min_assertions      计划断言数下限 (空断言集不得获得 MATCH)

裁决状态 (owner 修订):
  MATCH / DIVERGED / INCONCLUSIVE / BLOCKED / NOT_APPLICABLE / SKIPPED
  - MATCH          必需材料完整, 计划断言实际执行且全部成立
  - INCONCLUSIVE   缺必需材料/断言, 无法判定
  - SKIPPED        应执行而未执行的层; 必需层出现 SKIPPED 阻止整题通过

Deterministic-First: 门禁判定全部由契约与报告数据驱动, 无推断。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

VERDICT_MATCH = "MATCH"
VERDICT_DIVERGED = "DIVERGED"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_BLOCKED = "BLOCKED"
VERDICT_NOT_APPLICABLE = "NOT_APPLICABLE"
VERDICT_SKIPPED = "SKIPPED"


@dataclass
class EvaluationContract:
    case_id: str = ""
    required_layers: list[str] = field(default_factory=list)
    not_applicable_layers: list[str] = field(default_factory=list)
    required_artifacts: list[str] = field(default_factory=list)
    min_assertions: int = 1
    schema_version: str = "1.0"

    @classmethod
    def from_dict(cls, payload: dict) -> "EvaluationContract":
        return cls(
            case_id=str(payload.get("case_id") or ""),
            required_layers=[str(x) for x in (payload.get("required_layers") or [])],
            not_applicable_layers=[str(x) for x in (payload.get("not_applicable_layers") or [])],
            required_artifacts=[str(x) for x in (payload.get("required_artifacts") or [])],
            min_assertions=int(payload.get("min_assertions") or 1),
            schema_version=str(payload.get("schema_version") or "1.0"),
        )

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id, "schema_version": self.schema_version,
            "required_layers": self.required_layers,
            "not_applicable_layers": self.not_applicable_layers,
            "required_artifacts": self.required_artifacts,
            "min_assertions": self.min_assertions,
        }


def load_contract(case_dir: Path) -> EvaluationContract | None:
    p = Path(case_dir) / "evaluation_contract.json"
    if not p.exists():
        return None
    return EvaluationContract.from_dict(
        json.loads(p.read_text(encoding="utf-8")))


def count_assertions(report: dict) -> dict:
    """planned / executed / matched 断言计数 (阶段 0.1)。

    计划 = helpers×(semantic+roles) + expected_operations + machine_checks
           + allocator_events.per_call
    执行 = 早停之前实际比较过的计划项 (helper 层逐项 + 逐行 IR + 机器检查)
    匹配 = 执行且通过的项
    早停意味着「未执行」的层不虚报为通过 —— 由 SKIPPED 状态显式呈现。
    """
    planned = executed = matched = 0
    status = report.get("helper_contract_status") or []
    for h in status:
        planned += 2  # semantic + roles 每个helper至少两项断言
        if h.get("semantic") in ("MATCH",):
            executed += 2
            matched += 2
        else:
            # 偏差发生在哪一项, 另一项视为未执行 (早停纪律)
            executed += 1
    exp_ops = report.get("_expected_op_count") or 0
    planned += exp_ops
    for layer in report.get("layers_compared", []):
        if layer in ("STATIC_RECOGNITION", "CANONICAL_IR"):
            executed += exp_ops
            matched += exp_ops
            break
    machine_checks = report.get("_machine_check_count") or 0
    planned += machine_checks
    if "BINS" in report.get("layers_compared", []):
        executed += machine_checks
        matched += machine_checks
    return {"planned": planned, "executed": executed, "matched": matched}


def enforce(report: dict, contract: EvaluationContract | None) -> dict:
    """按契约对比较结果施加完整性门禁 (原 verdict 可能被升级/降级)。"""
    counts_default = count_assertions(report)
    report.setdefault("assertion_counts", counts_default)
    # 全局门禁 (无论有无契约): 空断言集不可能证明任何验收 — owner 记录的
    # 历史缺陷 (仅 case_id 真值 + 空输出曾得 MATCH) 在此拦截。
    if report.get("verdict") == VERDICT_MATCH and counts_default["planned"] == 0:
        report["verdict"] = VERDICT_INCONCLUSIVE
        report["assertion_counts"]["gate"] = "planned=0 (空断言集不得 MATCH)"
        return report
    if contract is None:
        return report

    layers_compared = set(report.get("layers_compared") or [])
    layer_results = {r.get("layer"): r for r in report.get("layer_results", [])}
    missing_required = [l for l in contract.required_layers if l not in layers_compared]
    counts = count_assertions(report)
    report["assertion_counts"] = counts

    report["contract_evaluation"] = {
        "required_layers": contract.required_layers,
        "missing_required_layers": missing_required,
        "not_applicable_layers": contract.not_applicable_layers,
        "required_artifacts": contract.required_artifacts,
        "min_assertions": contract.min_assertions,
    }

    # SKIPPED/NOT_APPLICABLE 状态标注
    for layer in contract.not_applicable_layers:
        if layer not in layers_compared:
            report["layer_results"].append(
                {"layer": layer, "status": VERDICT_NOT_APPLICABLE,
                 "semantic_status": VERDICT_NOT_APPLICABLE})
            report["layers_compared"].append(layer)
    for layer in contract.required_layers:
        if layer not in layers_compared:
            report["layer_results"].append(
                {"layer": layer, "status": VERDICT_SKIPPED,
                 "semantic_status": VERDICT_SKIPPED,
                 "missing_required": [layer]})

    # 门禁只拦截「虚假的 MATCH」。DIVERGED 是已完成的确定性判定
    # (材料足够且冲突已证), 保持原判; 缺失层仍以 SKIPPED 透明呈现。
    if report.get("verdict") != VERDICT_MATCH:
        return report

    # 门禁 1: 必需层被跳过 → 不得 MATCH
    skipped_required = [r for r in report["layer_results"]
                        if r.get("status") == VERDICT_SKIPPED
                        and r.get("layer") in contract.required_layers]
    if skipped_required:
        report["verdict"] = VERDICT_INCONCLUSIVE
        report["first_divergence"] = {
            "layer": skipped_required[0]["layer"], "step": None,
            "source_line": None, "source_call": None,
            "expected": {"executed": True},
            "actual": {"status": "SKIPPED"},
        }
        return report

    # 门禁 2: 空断言集不得 MATCH
    if counts["planned"] < contract.min_assertions:
        report["verdict"] = VERDICT_INCONCLUSIVE
        report["assertion_counts"]["gate"] = (
            f"planned={counts['planned']} < min_assertions={contract.min_assertions}")
        return report

    # 门禁 3: 计划断言未全部执行 (早停) → 不得 MATCH
    if counts["executed"] < counts["planned"]:
        report["verdict"] = VERDICT_INCONCLUSIVE
        report["assertion_counts"]["gate"] = (
            f"executed={counts['executed']} < planned={counts['planned']} "
            "(早停: 下游层未全部执行)")
        return report

    return report
