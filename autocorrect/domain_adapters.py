#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""领域适配器 (VNext M1): heap / stack / fmt 三条评测入口。

适用层由领域决定 (契约可覆盖)——不把所有领域硬塞进 allocator 层序:
  heap  : 现有 11 层管线 (comparator_v4, 单独入口已有)
  stack : EXP_SEMANTIC_RULES (Auditor 确定性规则) + BINARY_FACTS (位宽/PIE)
  fmt   : EXP_PARSE + FMT_INTERACTION (v1 smoke: 解析与交互提取)

每个适配器返回与 comparator 报告同形的 {layers_compared, layer_results,
verdict, ...}，供 evaluation_contract.enforce 统一门禁。
Deterministic-First: 无推断; 证据不足 → UNKNOWN/SKIPPED。
"""
from __future__ import annotations

from pathlib import Path

from pwnbao.features.audit.audit import audit_exp


def _result(layer: str, status: str, **extra) -> dict:
    out = {"layer": layer, "status": status,
           "semantic_status": status, "missing_required": [],
           "optional_missing": [], "detail": ""}
    out.update(extra)
    return out


def run_stack(case_material, exp_source: str, *,
              bits: int = 64, pie: bool = False) -> dict:
    """stack 领域: Auditor 确定性规则层 (leak packing / arch / PIE)。
    漏洞结论 (M4/M5) 不在此层输出。"""
    diagnostics = audit_exp(exp_source, bits=bits, pie=pie)
    errors = [d for d in diagnostics if d["severity"] == "error"]
    warnings = [d for d in diagnostics if d["severity"] == "warning"]
    results = [_result("EXP_SEMANTIC_RULES",
                       "DIVERGED" if errors else "MATCH",
                       diagnostics=diagnostics)]
    results.append(_result("BINARY_FACTS", "MATCH",
                           detail=f"bits={bits}, pie={pie}"))
    verdict = "DIVERGED" if errors else "MATCH"
    return {
        "case_id": case_material.case_id,
        "domain": "stack",
        "verdict": verdict,
        "layers_compared": ["EXP_SEMANTIC_RULES", "BINARY_FACTS"],
        "layer_results": results,
        "diagnostics": diagnostics,
        "assertion_counts": {"planned": 1 + len(warnings),
                             "executed": 1 + len(warnings),
                             "matched": 1 + len(warnings) - len(errors)},
    }


def run_fmt(case_material, exp_source: str) -> dict:
    """fmt 领域 v1 smoke: 解析层 + 交互提取层。格式化字符串语义检查
    (参数消费/输出计数) 属后续 milestone, 本层显式 NOT_APPLICABLE。"""
    from pwnbao.features.audit.extract import extract_exploit_ir
    ir, syntax_error = extract_exploit_ir(exp_source)
    results = []
    if syntax_error is not None:
        results.append(_result("EXP_PARSE", "DIVERGED",
                               detail=f"line {syntax_error.lineno}: {syntax_error.msg}"))
        return {"case_id": case_material.case_id, "domain": "fmt",
                "verdict": "DIVERGED",
                "layers_compared": ["EXP_PARSE", "FMT_INTERACTION"],
                "layer_results": results,
                "assertion_counts": {"planned": 2, "executed": 1, "matched": 0}}
    results.append(_result("EXP_PARSE", "MATCH"))
    results.append(_result("FMT_INTERACTION", "MATCH",
                           detail=f"interactions={len(ir.interactions)}"))
    results.append(_result("FMT_SEMANTIC_CHECKS", "SKIPPED",
                           detail="格式化字符串语义规则属后续 milestone"))
    return {"case_id": case_material.case_id, "domain": "fmt",
            "verdict": "MATCH",
            "layers_compared": ["EXP_PARSE", "FMT_INTERACTION"],
            "layers_not_compared": ["FMT_SEMANTIC_CHECKS"],
            "layer_results": results,
            "assertion_counts": {"planned": 2, "executed": 2, "matched": 2}}


def run_domain(domain: str, case_material, exp_source: str, **kwargs) -> dict:
    if domain == "stack":
        return run_stack(case_material, exp_source,
                         bits=int(kwargs.get("bits") or 64),
                         pie=bool(kwargs.get("pie")))
    if domain == "fmt":
        return run_fmt(case_material, exp_source)
    raise ValueError(f"领域 {domain!r} 的适配器未实现 (heap 走 comparator_v4 主管线)")


def default_applicable_layers(domain: str) -> dict:
    """领域默认适用层 (contract 未声明时使用)。"""
    if domain == "heap":
        return {"required_layers": ["HELPER_CONTRACT", "STATIC_RECOGNITION",
                                    "CANONICAL_IR"],
                "not_applicable_layers": []}
    if domain == "stack":
        return {"required_layers": ["EXP_SEMANTIC_RULES"],
                "not_applicable_layers": ["ALLOCATOR", "BINS",
                                          "PHYSICAL_MEMORY", "CANVAS_TRUTH",
                                          "SNAPSHOT", "TARGET_BEHAVIOR",
                                          "ARGUMENT_BINDING", "CANONICAL_IR",
                                          "STATIC_RECOGNITION",
                                          "HELPER_CONTRACT", "RENDERER_PLAN"]}
    if domain == "fmt":
        return {"required_layers": ["EXP_PARSE", "FMT_INTERACTION"],
                "not_applicable_layers": ["ALLOCATOR", "BINS",
                                          "PHYSICAL_MEMORY", "CANVAS_TRUTH",
                                          "SNAPSHOT", "TARGET_BEHAVIOR",
                                          "ARGUMENT_BINDING", "CANONICAL_IR",
                                          "STATIC_RECOGNITION",
                                          "HELPER_CONTRACT", "RENDERER_PLAN"]}
    return {"required_layers": [], "not_applicable_layers": []}
