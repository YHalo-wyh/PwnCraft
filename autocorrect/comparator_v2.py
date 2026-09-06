#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clean-room comparator (protocol v2, TRAINING_PROTOCOL.md locked).

Compares expected_truth.json (Phase A, locked) against PwnCraft generated
output (Phase B). Layer order is fixed by the protocol; comparison STOPS at
the first diverging layer:

  1 HELPER_CONTRACT        2 STATIC_RECOGNITION   3 CANONICAL_IR
  4 ARGUMENT_BINDING       5 ALLOCATOR            6 CHUNK_MAPPING
  7 PHYSICAL_MEMORY        8 BINS                 9 SNAPSHOT
 10 CANVAS

Implemented here: layers 1-5 (+8 via machine checks on replay snapshots).
Layers 6/7/9/10 need renderer/scene-model artifacts and are reported as
NOT_COMPARED (explicitly, never silently skipped).
"""
from __future__ import annotations

import json
from pathlib import Path

_SEMANTIC_ACTUAL = {
    "alloc": {"alloc", "allocate"},
    "free": {"free", "delete"},
    "edit": {"edit"},
    "show": {"show"},
    "copy": {"copy"},
    "unknown": {"unknown", "init", "value", ""},
}

_LAYER_ORDER = ["HELPER_CONTRACT", "STATIC_RECOGNITION", "CANONICAL_IR",
                "ARGUMENT_BINDING", "ALLOCATOR", "CHUNK_MAPPING",
                "PHYSICAL_MEMORY", "BINS", "SNAPSHOT", "CANVAS"]


def _concrete(av):
    if isinstance(av, dict) and av.get("kind") == "concrete":
        for k, v in av.items():
            if k not in ("kind", "source"):
                return v
    return None


def _matches(semantic, actual_op):
    return (actual_op or "unknown") in _SEMANTIC_ACTUAL.get(semantic, {semantic})


def _div(layer, step, line, call, expected, actual, component, reason_hint):
    return {
        "layer": layer,
        "step": step,
        "source_line": line,
        "source_call": call,
        "expected": expected,
        "actual": actual,
        "_component_hint": component,
        "_reason_hint": reason_hint,
    }


def compare(expected_truth: dict, actual: dict) -> dict:
    report = {
        "case_id": expected_truth.get("case_id"),
        "verdict": None,
        "first_divergence": None,
        "layers_compared": [],
        "layers_not_compared": ["CHUNK_MAPPING", "PHYSICAL_MEMORY", "SNAPSHOT", "CANVAS"],
        "root_cause": {"component": None, "reason": None},
        "evidence": [],
        "suggested_fix": {"scope": "generic", "description": None},
        "confidence": None,
    }
    analyzer = actual.get("analyzer") or {}
    contracts = {c["function"]: c for c in analyzer.get("helper_contracts", [])}
    canon_ops = [o for o in analyzer.get("canonical_ops", [])
                 if o.get("kind") not in ("init", "value")]
    ops_by_line = {o.get("source_line"): o for o in canon_ops}

    # ---------------- 1 HELPER_CONTRACT
    report["layers_compared"].append("HELPER_CONTRACT")
    for h in expected_truth.get("helpers", []):
        fn = h["function"]
        act = contracts.get(fn)
        exp_sem = h.get("semantic", "unknown")
        if act is None:
            report["first_divergence"] = _div(
                "HELPER_CONTRACT", None, h.get("_line"), f"def {fn}()",
                {"semantic": exp_sem, "roles": h.get("roles")},
                {"helper_contract": None},
                "HelperContractResolver", f"helper {fn} 无契约")
            return _finalize(report, h.get("evidence", []))
        act_op = act.get("operation")
        if not _matches(exp_sem, act_op):
            report["first_divergence"] = _div(
                "HELPER_CONTRACT", None, h.get("_line"), f"def {fn}()",
                {"semantic": exp_sem, "roles": h.get("roles"),
                 "helper_evidence": h.get("evidence")},
                {"operation": act_op, "confidence": act.get("confidence"),
                 "evidence_sources": act.get("evidence_sources"),
                 "roles": act.get("roles")},
                "HelperContractResolver",
                f"{fn} 语义判定 {act_op}, 证据支持 {exp_sem}")
            return _finalize(report, h.get("evidence", []))
        # roles: expected argN -> compare against binding at position N
        act_roles = act.get("roles") or {}
        pos_to_role = {}
        for role, b in act_roles.items():
            if isinstance(b, dict):
                p = b.get("position")
                if isinstance(p, int) and p >= 0:
                    pos_to_role[p] = role
        for arg_key, exp_role in sorted(h.get("roles", {}).items(),
                                        key=lambda kv: int(kv[0][3:]) if kv[0].startswith("arg") else 99):
            if exp_role in (None, "unknown", "null"):
                continue
            pos = int(arg_key[3:]) if arg_key.startswith("arg") else None
            act_role = pos_to_role.get(pos)
            if act_role != exp_role:
                report["first_divergence"] = _div(
                    "HELPER_CONTRACT", None, h.get("_line"),
                    f"def {fn}(): {arg_key}",
                    {"role": exp_role, "position": pos, "helper_evidence": h.get("evidence")},
                    {"bindings": act_roles, "observed_role_at_position": act_role},
                    "HelperContractResolver (argument binding)",
                    f"{fn} {arg_key} 期望角色 {exp_role}, 实际绑定 {act_role}")
                return _finalize(report, h.get("evidence", []))

    # ---------------- 2 STATIC_RECOGNITION + 3 CANONICAL_IR (by source line)
    report["layers_compared"].append("STATIC_RECOGNITION")
    report["layers_compared"].append("CANONICAL_IR")
    exp_ops = expected_truth.get("expected_operations", [])
    unmatched = [e for e in exp_ops if e.get("source_line") not in ops_by_line]
    if unmatched:
        u = unmatched[0]
        report["first_divergence"] = _div(
            "STATIC_RECOGNITION", None, u.get("source_line"), u.get("source_call"),
            {"call_site_recognized": True, "kind": u.get("kind")},
            {"recognized_at_line": None,
             "heap_ops_lines": sorted(ops_by_line.keys())},
            "HeapSourceAnalyzer recognition",
            f"调用点 {u.get('source_line')} 未被识别为堆操作")
        return _finalize(report, u.get("evidence", []))
    for e in exp_ops:
        o = ops_by_line[e["source_line"]]
        if not _matches(e.get("kind", "unknown"), o.get("kind")):
            report["first_divergence"] = _div(
                "CANONICAL_IR", o.get("step"), e["source_line"], e.get("source_call"),
                {"kind": e.get("kind"), "allocator_request": e.get("allocator_request")},
                {"kind": o.get("kind"), "handle": o.get("handle"),
                 "allocator_request": o.get("allocator_request")},
                "Canonical IR conversion",
                f"L{e['source_line']} IR kind={o.get('kind')}, 期望 {e.get('kind')}")
            return _finalize(report, e.get("evidence", []))

    # ---------------- 4 ARGUMENT_BINDING (handle of index-carrying ops)
    report["layers_compared"].append("ARGUMENT_BINDING")
    for e in exp_ops:
        if e.get("kind") in ("alloc",):
            continue  # alloc 的槽位由分配序推导, 归入 allocator/chunk 层
        o = ops_by_line[e["source_line"]]
        av = _concrete(o.get("handle"))
        exp_idx = (e.get("arguments") or {}).get("arg0")
        if isinstance(exp_idx, str) and exp_idx.startswith("0x"):
            try:
                exp_idx = int(exp_idx, 16)
            except ValueError:
                exp_idx = None
        if isinstance(exp_idx, int) and av is not None and av != exp_idx:
            report["first_divergence"] = _div(
                "ARGUMENT_BINDING", o.get("step"), e["source_line"], e.get("source_call"),
                {"handle": exp_idx},
                {"handle": av, "handle_raw": o.get("handle")},
                "HelperContract argument binding → IR handle",
                f"L{e['source_line']} 作用槽位 {av}, 期望 {exp_idx}")
            return _finalize(report, e.get("evidence", []))

    # ---------------- 5 ALLOCATOR (allocator_request + machine checks on replay)
    report["layers_compared"].append("ALLOCATOR")
    for e in exp_ops:
        if e.get("kind") != "alloc":
            continue
        o = ops_by_line[e["source_line"]]
        exp_req = e.get("allocator_request")
        act_req = _concrete(o.get("allocator_request"))
        exp_val = None
        if isinstance(exp_req, str):
            try:
                exp_val = int(exp_req, 16) if exp_req.lower().startswith("0x") else int(exp_req)
            except ValueError:
                exp_val = None
        if exp_val is not None and act_req != exp_val:
            report["first_divergence"] = _div(
                "ALLOCATOR", o.get("step"), e["source_line"], e.get("source_call"),
                {"allocator_request": exp_req, "evidence": e.get("evidence")},
                {"allocator_request": o.get("allocator_request")},
                "HelperContract allocator_request derivation",
                f"L{e['source_line']} allocator_request={act_req}, 期望 {exp_req}")
            return _finalize(report, e.get("evidence", []))
    failures = _machine_checks(expected_truth.get("machine_checks", []),
                               actual.get("replay") or {}, ops_by_line, canon_ops)
    if failures:
        f = failures[0]
        report["first_divergence"] = _div(
            "ALLOCATOR", f.get("step"), f.get("after_line"), None,
            {"check": f["check"], "fact": f.get("fact"), "expected": f.get("value"),
             "evidence": f.get("evidence")},
            {"observed": f.get("observed"), "step": f.get("step")},
            "GlibcHeapEngine allocator model",
            f["hint"])
        return _finalize(report, f.get("evidence", []))

    report["verdict"] = "MATCH"
    return report


def _finalize(report, evidence):
    report["verdict"] = "DIVERGED"
    report["evidence"] = list(evidence or [])
    fd = report.get("first_divergence") or {}
    report["root_cause"]["component"] = fd.get("_component_hint")
    report["root_cause"]["reason"] = None  # Reviewer 定稿
    report["suggested_fix"]["description"] = None  # Reviewer 定稿
    report["confidence"] = None
    for k in ("_component_hint", "_reason_hint"):
        fd.pop(k, None)
    return report


def _machine_checks(checks, replay, ops_by_line, canon_ops):
    steps = {s.get("step"): s for s in (replay.get("steps") or []) if isinstance(s, dict)}
    failures = []
    for chk in checks or []:
        line = chk.get("after_line")
        op = ops_by_line.get(line)
        if op is None:
            continue
        st = steps.get(op.get("step"))
        if st is None:
            continue
        kind = chk.get("check")
        ok, observed, hint = True, "", ""
        if kind == "live_chunks":
            ok = st.get("n_chunks") == chk.get("value")
            observed = f"n_chunks={st.get('n_chunks')}"
            hint = f"L{line} 后存活 chunk 数与 binary 真值不符"
        elif kind in ("bin_nonempty", "bin_empty"):
            bins = st.get(chk.get("bin") or "fastbins") or {}
            sc = chk.get("size_class")
            if isinstance(bins, dict):
                if sc:
                    lst = bins.get(sc) or bins.get(sc.replace("0x", "")) or []
                    n = len(lst) if isinstance(lst, list) else (1 if lst else 0)
                else:
                    n = sum(len(v) for v in bins.values() if isinstance(v, list))
            else:
                n = len(bins) if isinstance(bins, list) else 0
            ok = (n > 0) if kind == "bin_nonempty" else (n == 0)
            observed = f"{chk.get('bin')}={bins}"
            hint = f"L{line} 后 {chk.get('bin')}" + (f"[{sc}]" if sc else "") + \
                   ("应有 chunk 但为空" if kind == "bin_nonempty" else "应为空但非空")
        else:
            continue
        if not ok:
            failures.append({"check": kind, "after_line": line, "step": st.get("step"),
                             "fact": chk.get("fact"), "value": chk.get("value"),
                             "observed": observed, "hint": hint,
                             "evidence": chk.get("evidence")})
    return failures
