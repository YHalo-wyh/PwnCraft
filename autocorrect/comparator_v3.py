#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clean-room comparator v3 (protocol v1.1 + v1.2).

Upgrades over v2 (owner amendments, TRAINING_PROTOCOL.md v1.1/v1.2):
  * HelperContract compared as a six-field tuple: semantic, argument_roles,
    confidence, evidence_type, evidence, provenance.
  * Verdicts distinguish SEMANTIC_MATCH with EVIDENCE_DIVERGED ("right answer,
    wrong reasoning" IS a divergence) from SEMANTIC_DIVERGED.
  * Provenance is independently re-derived from the EXP source per v1.2 §H:
    SHOW structurally requires OUTPUT_DATA_FLOW (consumed recv-family results);
    PROMPT_SYNC only proves sync/binding; FREE/DELETE never depends on
    OUTPUT_DATA_FLOW (own positive-evidence path) and gets no provenance
    complaint for lacking it.
  * TARGET_BEHAVIOR layer (v1.2 §I): binary/source internal actions (1:N —
    one helper call may map to several allocator events; create =
    malloc(0x10)+malloc(size), delete = free(content)+free(struct) — two free
    calls, NOT double_free). HelperContract is not blamed for these.

Layer order (protocol v1.2 §I):
  HELPER_CONTRACT -> STATIC_RECOGNITION -> CANONICAL_IR -> ARGUMENT_BINDING
  -> TARGET_BEHAVIOR -> ALLOCATOR -> BINS
  (CHUNK_MAPPING / PHYSICAL_MEMORY / SNAPSHOT / CANVAS: not compared yet)
"""
from __future__ import annotations

import ast
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

# evidence tier ranking (higher = stronger provenance)
TIER_RANK = {
    "name_heuristic": 0,           # NAME_CANDIDATE
    "alias": 1,                    # SAFE_ALIAS / wrapper propagation
    "interaction_dataflow": 2,     # structural body: prompt→parameter dataflow
    "binary_source_dataflow": 3,   # malloc/free/read/write dataflow in binary/source
}
ACTUAL_SOURCE_TIER = {
    "NAME_CANDIDATE": "name_heuristic",
    "SAFE_ALIAS": "alias",
    "WRAPPER": "alias",
    "STRUCTURAL_BODY": "interaction_dataflow",
    "INLINE_ANNOTATION": "interaction_dataflow",
    "IMPORTED_PROFILE": "interaction_dataflow",
    "USER_CONFIRMED": "binary_source_dataflow",
}

_RECV = {"recv", "recvn", "recvline", "recvuntil", "read", "readline", "ru", "rl"}


# ---------------------------------------------------------------- provenance

def helper_body_output_dataflow(exp_source: str, function: str) -> dict:
    """Independently re-derive (from the EXP source alone) whether the helper
    body contains OUTPUT_DATA_FLOW, per protocol v1.2 §H:

      consumed (not a bare expression statement: assigned / returned / printed
      / flows into a computation) recv-family call  -> OUTPUT_DATA_FLOW
      discarded recvuntil                              -> PROMPT_SYNC candidate
      discarded recv/recvn/recvline (value dropped)    -> no data flow

    This is the Reviewer's own implementation, deliberately independent of the
    recognizer's internals. FREE/DELETE never depends on this check."""
    try:
        tree = ast.parse(exp_source)
    except SyntaxError:
        return {"parse_ok": False}
    fn = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == function:
            fn = node
            break
    if fn is None:
        return {"parse_ok": True, "found": False}
    discarded = set()
    for parent in ast.walk(fn):
        if isinstance(parent, ast.Expr) and isinstance(parent.value, ast.Call):
            discarded.add(id(parent.value))
    prompt_syncs = output_flows = 0
    for child in ast.walk(fn):
        if not isinstance(child, ast.Call):
            continue
        name = child.func.id if isinstance(child.func, ast.Name) else \
            (child.func.attr if isinstance(child.func, ast.Attribute) else "")
        if name not in _RECV and not name.startswith("recv"):
            continue
        if id(child) in discarded:
            if name == "recvuntil":
                prompt_syncs += 1          # PROMPT_SYNC candidate (sync/binding only)
            # discarded non-until recv: value dropped, no data flow (v1.2 §H)
        else:
            output_flows += 1              # consumed: OUTPUT_DATA_FLOW
    return {"parse_ok": True, "found": True, "prompt_syncs": prompt_syncs,
            "output_flows": output_flows}


# ---------------------------------------------------------------- compare

def _normalize_truth(expected_truth: dict) -> dict:
    """Support both layouts: flat (cycle-1 lab13, locked) and layered
    (v1.2 §5 four-truth separation: exp_wrapper_truth / target_behavior_truth /
    allocator_truth / physical_truth). Returns a flat view for comparison."""
    if not any(k in expected_truth for k in
               ("exp_wrapper_truth", "target_behavior_truth", "allocator_truth", "physical_truth")):
        return expected_truth
    ew = expected_truth.get("exp_wrapper_truth") or {}
    tb = expected_truth.get("target_behavior_truth") or {}
    al = expected_truth.get("allocator_truth") or {}
    flat = dict(expected_truth)
    flat.setdefault("helpers", ew.get("helpers", expected_truth.get("helpers", [])))
    flat.setdefault("expected_operations", ew.get("expected_operations", expected_truth.get("expected_operations", [])))
    flat.setdefault("target_behavior", tb if tb else expected_truth.get("target_behavior"))
    flat.setdefault("allocator_events", al.get("allocator_events", expected_truth.get("allocator_events", {})))
    flat.setdefault("machine_checks", al.get("machine_checks", expected_truth.get("machine_checks", [])))
    return flat


def compare(expected_truth_raw: dict, actual: dict, exp_source: str = "") -> dict:
    expected_truth = _normalize_truth(expected_truth_raw)
    report = {
        "case_id": expected_truth_raw.get("case_id"),
        "verdict": None,
        "first_divergence": None,
        "helper_contract_status": [],
        "layers_compared": [],
        "layers_not_compared": ["CHUNK_MAPPING", "PHYSICAL_MEMORY", "SNAPSHOT"],
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

    # ---------------- 0 EXP_PARSE (pipeline stage "EXP", before recognition)
    diagnostics = analyzer.get("diagnostics") or []
    syntax_errors = [d for d in diagnostics if "syntax_error" in str(d)]
    if analyzer.get("valid") is False and syntax_errors:
        return _halt(report, {"layer_detail": "syntax_error"},
                     "EXP_PARSE", None, None,
                     {"parseable": True,
                      "note": "expected_truth 锁定于 EXP 源码; py2 方言属 EXP 方言维度"},
                     {"valid": analyzer.get("valid"),
                      "diagnostics": syntax_errors[:3],
                      "helper_contracts": len(contracts),
                      "canonical_ops": len(canon_ops)},
                     "EXP source parser (ast.parse at analyzer/resolver entry)",
                     expected_truth.get("uncertainties", [])[:1],
                     "EXP 无法解析 (py2 print 语句等方言), 全下游层不可用")

    # ---------------- 1 HELPER_CONTRACT (six-field comparison)
    report["layers_compared"].append("HELPER_CONTRACT")
    for h in expected_truth.get("helpers", []):
        fn = h["function"]
        act = contracts.get(fn)
        exp_sem = h.get("semantic", "unknown")
        status = {"helper": fn, "expected_semantic": exp_sem}
        if act is None:
            status.update({"semantic": "SEMANTIC_DIVERGED", "actual": None,
                           "divergence_field": "semantic"})
            report["helper_contract_status"].append(status)
            return _halt(report, status, "HELPER_CONTRACT", h.get("_line"), f"def {fn}()",
                         {"semantic": exp_sem}, {"contract": None},
                         "HelperContractResolver", h.get("evidence", []),
                         f"helper {fn} 无契约")
        act_op = act.get("operation")
        sem_match = _matches(exp_sem, act_op)
        status["actual_operation"] = act_op
        status["actual_candidate_operation"] = act.get("candidate_operation")
        status["actual_confidence"] = act.get("confidence")

        # (a) semantic field
        if not sem_match:
            status.update({"semantic": "SEMANTIC_DIVERGED", "divergence_field": "semantic"})
            report["helper_contract_status"].append(status)
            return _halt(report, status, "HELPER_CONTRACT", h.get("_line"), f"def {fn}()",
                         {"semantic": exp_sem, "roles": h.get("roles"),
                          "helper_evidence": h.get("evidence")},
                         {"operation": act_op, "confidence": act.get("confidence"),
                          "evidence": act.get("evidence")},
                         "HelperContractResolver", h.get("evidence", []),
                         f"{fn} 语义判定 {act_op}, 证据支持 {exp_sem}")

        # (b) argument_roles field
        act_roles = act.get("roles") or {}
        pos_to_role = {b.get("position"): role for role, b in act_roles.items()
                       if isinstance(b, dict) and isinstance(b.get("position"), int) and b["position"] >= 0}
        for arg_key, exp_role in sorted(h.get("roles", {}).items(),
                                        key=lambda kv: int(kv[0][3:]) if kv[0].startswith("arg") else 99):
            if exp_role in (None, "unknown", "null"):
                continue
            pos = int(arg_key[3:]) if arg_key.startswith("arg") else None
            if pos_to_role.get(pos) != exp_role:
                status.update({"semantic": "SEMANTIC_DIVERGED",
                               "divergence_field": "argument_roles",
                               "expected_role": {arg_key: exp_role},
                               "observed_bindings": act_roles})
                report["helper_contract_status"].append(status)
                return _halt(report, status, "HELPER_CONTRACT", h.get("_line"),
                             f"def {fn}(): {arg_key}",
                             {"role": exp_role, "position": pos},
                             {"bindings": act_roles},
                             "HelperContractResolver (argument binding)",
                             h.get("evidence", []),
                             f"{fn} {arg_key} 期望角色 {exp_role}, 实际绑定 {pos_to_role.get(pos)}")

        # (c) evidence_type / provenance: SEMANTIC_MATCH can still EVIDENCE_DIVERGE
        exp_tier = h.get("evidence_tier", "interaction_dataflow")
        actual_sources = act.get("evidence_sources") or []
        actual_tier = max((TIER_RANK.get(ACTUAL_SOURCE_TIER.get(s, "name_heuristic"), 0)
                           for s in actual_sources), default=0)
        provenance_check = helper_body_output_dataflow(exp_source, fn) if exp_source else {"parse_ok": None}
        unsound_provenance = None
        if actual_sources and "STRUCTURAL_BODY" in actual_sources and provenance_check.get("found"):
            body = provenance_check
            # v1.2 §H: ONLY SHOW requires OUTPUT_DATA_FLOW as its strong
            # structural evidence. FREE/DELETE never depends on it (independent
            # positive evidence path), so no provenance complaint here for free.
            if exp_sem == "show" and not body.get("output_flows"):
                unsound_provenance = (
                    f"{fn} 的函数体无任何输出数据流 (prompt_syncs={body.get('prompt_syncs')}, "
                    f"output_flows=0), 但契约以 STRUCTURAL_BODY 证据判定 {act_op}; "
                    "该证据只能来自 prompt-sync 误判 (index+recvuntil(prompt))"
                )
        under_proven = TIER_RANK.get(exp_tier, 2) >= TIER_RANK["interaction_dataflow"] and \
            actual_tier < TIER_RANK["interaction_dataflow"]
        if unsound_provenance or under_proven:
            status.update({
                "semantic": "SEMANTIC_MATCH",
                "evidence": "EVIDENCE_DIVERGED",
                "divergence_field": "evidence_type/provenance",
                "expected_evidence_tier": exp_tier,
                "actual_evidence_sources": actual_sources,
                "provenance_recheck": provenance_check,
                "unsound_provenance": unsound_provenance,
            })
            report["helper_contract_status"].append(status)
            return _halt(report, status, "HELPER_CONTRACT", h.get("_line"), f"def {fn}()",
                         {"semantic": exp_sem, "evidence_tier": exp_tier,
                          "evidence": h.get("evidence")},
                         {"operation": act_op, "evidence_sources": actual_sources,
                          "evidence": act.get("evidence"),
                          "provenance_recheck": provenance_check},
                         "HelperContractResolver (evidence provenance)",
                         h.get("evidence", []),
                         unsound_provenance or
                         f"{fn} 语义碰巧正确, 但证据等级 {actual_sources} 低于期望 {exp_tier}")

        status["semantic"] = "MATCH"
        report["helper_contract_status"].append(status)

    # ---------------- 2 STATIC_RECOGNITION / 3 CANONICAL_IR
    report["layers_compared"].append("STATIC_RECOGNITION")
    report["layers_compared"].append("CANONICAL_IR")
    exp_ops = expected_truth.get("expected_operations", [])
    unmatched = [e for e in exp_ops if e.get("source_line") not in ops_by_line]
    if unmatched:
        u = unmatched[0]
        return _halt(report, {"layer_detail": "call site not recognized"},
                     "STATIC_RECOGNITION", u.get("source_line"), u.get("source_call"),
                     {"call_site_recognized": True, "kind": u.get("kind")},
                     {"heap_ops_lines": sorted(ops_by_line.keys())},
                     "HeapSourceAnalyzer recognition", u.get("evidence", []),
                     f"调用点 {u.get('source_line')} 未被识别为堆操作")
    for e in exp_ops:
        o = ops_by_line[e["source_line"]]
        if not _matches(e.get("kind", "unknown"), o.get("kind")):
            return _halt(report, {"layer_detail": "ir kind"},
                         "CANONICAL_IR", e["source_line"], e.get("source_call"),
                         {"kind": e.get("kind"), "allocator_request": e.get("allocator_request")},
                         {"kind": o.get("kind"), "handle": o.get("handle"),
                          "allocator_request": o.get("allocator_request")},
                         "Canonical IR conversion", e.get("evidence", []),
                         f"L{e['source_line']} IR kind={o.get('kind')}, 期望 {e.get('kind')}")

    # ---------------- 4 ARGUMENT_BINDING
    report["layers_compared"].append("ARGUMENT_BINDING")
    for e in exp_ops:
        if e.get("kind") == "alloc":
            continue
        o = ops_by_line[e["source_line"]]
        av = _concrete(o.get("handle"))
        exp_idx = (e.get("arguments") or {}).get("arg0")
        if isinstance(exp_idx, str) and exp_idx.startswith("0x"):
            try:
                exp_idx = int(exp_idx, 16)
            except ValueError:
                exp_idx = None
        if isinstance(exp_idx, int) and av is not None and av != exp_idx:
            return _halt(report, {"layer_detail": "handle"},
                         "ARGUMENT_BINDING", e["source_line"], e.get("source_call"),
                         {"handle": exp_idx}, {"handle": av, "raw": o.get("handle")},
                         "HelperContract argument binding → IR handle",
                         e.get("evidence", []),
                         f"L{e['source_line']} 作用槽位 {av}, 期望 {exp_idx}")

    # ---------------- TARGET_BEHAVIOR (protocol v1.2 §I)
    # Binary/source-level internal actions (e.g. create -> malloc(0x10) +
    # malloc(size)). HelperContract is NOT blamed for failing to infer these
    # from the EXP alone; the pipeline owes them to the TargetBehavior stage.
    report["layers_compared"].append("TARGET_BEHAVIOR")
    tb_fail = _allocator_events_check(expected_truth.get("allocator_events") or {},
                                       actual.get("replay") or {}, ops_by_line)
    if tb_fail:
        return _halt(report, {"layer_detail": "target_behavior"},
                     "TARGET_BEHAVIOR", tb_fail["after_line"], tb_fail.get("call"),
                     tb_fail["expected"], tb_fail["actual"],
                     "TargetBehavior stage (binary/source internal actions; "
                     "not a HelperContract deficiency)",
                     tb_fail.get("evidence", []), tb_fail["hint"])

    # ---------------- 5 ALLOCATOR (per-op request + machine checks)
    report["layers_compared"].append("ALLOCATOR")
    for e in exp_ops:
        if e.get("kind") != "alloc":
            continue
        o = ops_by_line[e["source_line"]]
        exp_req = e.get("allocator_request")
        act_req = _concrete(o.get("allocator_request"))
        if isinstance(exp_req, str) and act_req is not None:
            try:
                exp_val = int(exp_req, 16) if exp_req.lower().startswith("0x") else int(exp_req)
            except ValueError:
                exp_val = None
            if exp_val is not None and act_req != exp_val:
                return _halt(report, {"layer_detail": "allocator_request"},
                             "ALLOCATOR", e["source_line"], e.get("source_call"),
                             {"allocator_request": exp_req},
                             {"allocator_request": o.get("allocator_request")},
                             "HelperContract allocator_request derivation",
                             e.get("evidence", []),
                             f"L{e['source_line']} allocator_request={act_req}, 期望 {exp_req}")
    fail = _allocator_events_check(expected_truth.get("allocator_events") or {},
                                   actual.get("replay") or {}, ops_by_line)
    if fail:
        return _halt(report, {"layer_detail": "allocator_events"},
                     "ALLOCATOR", fail["after_line"], fail.get("call"),
                     fail["expected"], fail["actual"],
                     "GlibcHeapEngine allocator event model (1:N)",
                     fail.get("evidence", []), fail["hint"])

    # ---------------- 8 BINS (machine checks)
    report["layers_compared"].append("BINS")
    failures = _machine_checks(expected_truth.get("machine_checks", []),
                               actual.get("replay") or {}, ops_by_line)
    if failures:
        f = failures[0]
        return _halt(report, {"layer_detail": "bins"},
                     "BINS", f.get("after_line"), None,
                     {"check": f["check"], "fact": f.get("fact"), "value": f.get("value")},
                     {"observed": f.get("observed")},
                     "GlibcHeapEngine allocator model",
                     f.get("evidence", []), f["hint"])

    # ---------------- CANVAS_SEMANTIC_MODEL (pre-render semantic truth layer)
    report["layers_compared"].append("CANVAS_SEMANTIC_MODEL")
    canvas_invs = actual.get("canvas_invariants") or []
    bad_steps = [r for r in canvas_invs if r.get("violations")]
    if bad_steps:
        b = bad_steps[0]
        v = b["violations"][0]
        return _halt(report, {"layer_detail": "canvas_invariant"},
                     "CANVAS_SEMANTIC_MODEL", None, None,
                     {"invariant": v["invariant"], "holds": True},
                     {"step": b["step"], "violation": v},
                     "canvas_model.py / renderer semantic inputs",
                     [f"step {b['step']} invariant {v['invariant']}: {v['what']}"],
                     f"canvas invariant {v['invariant']} violated at step {b['step']}")

    report["verdict"] = "MATCH"
    return report


def _halt(report, status_detail, layer, line, call, expected, actual, component, evidence, reason):
    report["verdict"] = "DIVERGED"
    report["first_divergence"] = {
        "layer": layer,
        "step": None,
        "source_line": line,
        "source_call": call,
        "expected": expected,
        "actual": actual,
        "status_detail": status_detail,
    }
    report["root_cause"] = {"component": component, "reason": None}  # Reviewer 定稿
    report["evidence"] = list(evidence or [])
    report["reviewer_reason_hint"] = reason
    return report


def _allocator_events_check(alloc_events_truth, replay, ops_by_line):
    """1:N: expected allocator events per helper call vs actual step events."""
    per_call = alloc_events_truth.get("per_call") or []
    steps = {s.get("step"): s for s in (replay.get("steps") or []) if isinstance(s, dict)}
    for spec in per_call:
        op = ops_by_line.get(spec.get("source_line"))
        if op is None:
            continue
        st = steps.get(op.get("step"))
        if st is None:
            continue
        exp_events = spec.get("events") or []
        exp_mallocs = [e for e in exp_events if e.get("kind") == "malloc"]
        exp_frees = [e for e in exp_events if e.get("kind") == "free"]
        act_allocs = st.get("alloc_events") or []
        act_frees = st.get("free_events") or []
        if exp_mallocs and len(act_allocs) != len(exp_mallocs):
            return {
                "after_line": spec["source_line"], "call": spec.get("call"),
                "expected": {"malloc_event_count": len(exp_mallocs),
                             "requests": [e.get("request") for e in exp_mallocs],
                             "note": "one helper call -> N allocator events"},
                "actual": {"malloc_event_count": len(act_allocs),
                           "events": act_allocs},
                "hint": (f"L{spec['source_line']} {spec.get('call')}: binary 真值为 "
                         f"{len(exp_mallocs)} 次 malloc ({' + '.join(e.get('request') or '?' for e in exp_mallocs)}), "
                         f"识别/模拟只产生 {len(act_allocs)} 个 alloc event — 1:N allocator event 缺失"),
                "evidence": [ev for e in exp_mallocs for ev in e.get("evidence", [])],
            }
        if exp_frees and len(act_frees) != len(exp_frees):
            return {
                "after_line": spec["source_line"], "call": spec.get("call"),
                "expected": {"free_event_count": len(exp_frees),
                             "note": "two free calls (free(content)+free(struct)), NOT double_free"},
                "actual": {"free_event_count": len(act_frees), "events": act_frees},
                "hint": (f"L{spec['source_line']} {spec.get('call')}: 真值为 {len(exp_frees)} 次 free 调用, "
                         f"模拟产生 {len(act_frees)} 个 free event"),
                "evidence": [ev for e in exp_frees for ev in e.get("evidence", [])],
            }
    return None


def _machine_checks(checks, replay, ops_by_line):
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
        ok, observed = True, ""
        if kind == "live_chunks":
            ok = st.get("n_chunks") == chk.get("value")
            observed = f"n_chunks={st.get('n_chunks')}"
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
        else:
            continue
        if not ok:
            failures.append({"check": kind, "after_line": line, "fact": chk.get("fact"),
                             "value": chk.get("value"), "observed": observed,
                             "hint": f"L{line} 后 {chk.get('fact')}",
                             "evidence": chk.get("evidence")})
    return failures


def _concrete(av):
    if isinstance(av, dict) and av.get("kind") == "concrete":
        for k, v in av.items():
            if k not in ("kind", "source"):
                return v
    return None


def _matches(semantic, actual_op):
    return (actual_op or "unknown") in _SEMANTIC_ACTUAL.get(semantic, {semantic})
