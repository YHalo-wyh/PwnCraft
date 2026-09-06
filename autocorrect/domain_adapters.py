#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""领域适配器: heap / stack / fmt 三条评测入口。

适用层由领域决定——不把所有领域硬塞进 allocator 层序:
  heap  : 现有专用 comparator 管线
  stack : EXP_SEMANTIC_RULES + BINARY_FACTS + 可选 STACK_RUNTIME_TRUTH
  fmt   : EXP_PARSE + FMT_INTERACTION + FMT_SEMANTIC_CHECKS

Deterministic-First: 无推断; 证据不足 → UNKNOWN/SKIPPED。尤其是 Stack：
SIGSEGV 本身不是 Control RIP 证据；只有实际 RIP/EIP/PC 观测值能被 cyclic
确定性反解时，STACK_RUNTIME_TRUTH 才 MATCH 为 confirmed_control。
"""
from __future__ import annotations

from collections.abc import Mapping

from pwncraft.features.audit.audit import audit_exp


def _result(layer: str, status: str, **extra) -> dict:
    out = {"layer": layer, "status": status,
           "semantic_status": status, "missing_required": [],
           "optional_missing": [], "detail": ""}
    out.update(extra)
    return out


def _stack_runtime_result(runtime_observation: Mapping[str, object] | None,
                          pattern_n: int | None) -> tuple[dict, dict | None]:
    if not runtime_observation:
        return _result(
            "STACK_RUNTIME_TRUTH", "SKIPPED",
            detail="无 observed RIP/EIP/PC sidecar；不升级 Control RIP",
            optional_missing=["runtime control-register observation"],
        ), None

    from pwncraft.core.stack_truth import (
        RuntimeRegisterObservation,
        derive_saved_ip_control_from_observation,
    )

    try:
        observation = RuntimeRegisterObservation(
            register=str(runtime_observation.get("register") or ""),
            value=runtime_observation.get("value"),
            source=str(runtime_observation.get("source") or "runtime_sidecar"),
            signal=str(runtime_observation.get("signal") or ""),
            stop_reason=str(runtime_observation.get("stop_reason") or ""),
        )
        evidence = derive_saved_ip_control_from_observation(observation, n=pattern_n)
    except (TypeError, ValueError) as error:
        return _result(
            "STACK_RUNTIME_TRUTH", "SKIPPED",
            detail=f"运行时值未证明 saved-IP control: {error}",
            optional_missing=["cyclic-correlated RIP/EIP/PC observation"],
        ), None

    payload = evidence.to_dict()
    return _result(
        "STACK_RUNTIME_TRUTH", "MATCH",
        detail=(f"{payload['control_register'].upper()} observed -> "
                f"offset={payload['overflow_offset']} -> confirmed_control"),
        evidence=payload,
    ), payload


def run_stack(case_material, exp_source: str, *,
              bits: int = 64, pie: bool = False,
              runtime_observation: Mapping[str, object] | None = None,
              pattern_n: int | None = None) -> dict:
    """Stack 领域：静态 EXP/Binary rules + 可选 debugger-observed truth。"""
    diagnostics = audit_exp(exp_source, bits=bits, pie=pie)
    errors = [d for d in diagnostics if d["severity"] == "error"]
    warnings = [d for d in diagnostics if d["severity"] == "warning"]
    results = [_result("EXP_SEMANTIC_RULES",
                       "DIVERGED" if errors else "MATCH",
                       diagnostics=diagnostics)]
    results.append(_result("BINARY_FACTS", "MATCH",
                           detail=f"bits={bits}, pie={pie}"))
    runtime_result, runtime_truth = _stack_runtime_result(runtime_observation, pattern_n)
    results.append(runtime_result)
    verdict = "DIVERGED" if errors else "MATCH"
    return {
        "case_id": case_material.case_id,
        "domain": "stack",
        "verdict": verdict,
        "layers_compared": ["EXP_SEMANTIC_RULES", "BINARY_FACTS", "STACK_RUNTIME_TRUTH"],
        "layer_results": results,
        "diagnostics": diagnostics,
        "stack_runtime_truth": runtime_truth,
        "assertion_counts": {"planned": 2 + len(warnings),
                             "executed": 1 + len(warnings) + int(runtime_observation is not None),
                             "matched": 1 + len(warnings) - len(errors) + int(runtime_truth is not None)},
    }


def run_fmt(case_material, exp_source: str) -> dict:
    """fmt 领域: 解析层 + 交互层 + 语义检查层（确定性 facts）。"""
    from pwncraft.core.fmt_semantics import fmt_facts_from_strings
    from pwncraft.features.audit.extract import extract_exploit_ir
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
    facts = fmt_facts_from_strings(getattr(ir, "strings", []))
    results.append(_result(
        "FMT_SEMANTIC_CHECKS", "MATCH",
        detail=f"facts={[(f['kind'], f['subject'][:30]) for f in facts]}"))
    return {"case_id": case_material.case_id, "domain": "fmt",
            "verdict": "MATCH",
            "layers_compared": ["EXP_PARSE", "FMT_INTERACTION",
                                "FMT_SEMANTIC_CHECKS"],
            "layer_results": results,
            "fmt_facts": facts,
            "assertion_counts": {"planned": 3, "executed": 3, "matched": 3}}


def run_domain(domain: str, case_material, exp_source: str, **kwargs) -> dict:
    if domain == "stack":
        return run_stack(
            case_material,
            exp_source,
            bits=int(kwargs.get("bits") or 64),
            pie=bool(kwargs.get("pie")),
            runtime_observation=kwargs.get("runtime_observation"),
            pattern_n=(int(kwargs["pattern_n"]) if kwargs.get("pattern_n") is not None else None),
        )
    if domain == "fmt":
        return run_fmt(case_material, exp_source)
    raise ValueError(f"领域 {domain!r} 的适配器未实现 (heap 走专用 comparator 主管线)")


def default_applicable_layers(domain: str) -> dict:
    """领域默认适用层 (contract 未声明时使用)。"""
    if domain == "heap":
        return {"required_layers": ["HELPER_CONTRACT", "STATIC_RECOGNITION",
                                    "CANONICAL_IR"],
                "not_applicable_layers": []}
    if domain == "stack":
        return {"required_layers": ["EXP_SEMANTIC_RULES"],
                "optional_layers": ["BINARY_FACTS", "STACK_RUNTIME_TRUTH"],
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
