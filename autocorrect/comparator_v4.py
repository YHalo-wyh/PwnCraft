#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comparator v4.1 (EVIDENCE-SCOPE-CLOSURE).

Evidence Ownership (this round's core change):
  HELPER_CONTRACT   owns EXP wrapper semantics. Required evidence is EXP-side
                    only (prompt→send / callsite dataflow / wrapper dataflow).
                    SOURCE/BINARY evidence is OPTIONAL CORROBORATING: its
                    absence can never fail the layer.
  TARGET_BEHAVIOR   owns target-internal actions. Requires SOURCE/BINARY
                    internal-action flow; insufficient evidence -> UNKNOWN.
  ALLOCATOR         owns confirmed target actions -> glibc events.
  PHYSICAL_MEMORY   owns allocator/write actions -> physical byte/range truth.
  CANVAS            never serves as truth evidence for any layer above.

Carries forward INFRA-CLOSURE-1:
  P0-1 op_id alignment everywhere (never positional; anti-positional tests).
  P0-2 run_id gate refuses mixed artifacts.
  P0-3 TARGET_BEHAVIOR / ALLOCATOR are separate layers with separate checks.
  P0-4 PHYSICAL_MEMORY / SNAPSHOT are real artifact layers.
  P0-5 CANVAS_TRUTH vs RENDERER_PLAN five special checks.
  P1-3 six-field structured helper comparison; py2-tolerant minimal def-use
       for OUTPUT_DATA_FLOW (assignment alone is NOT consumption).

Layer order:
  HELPER_CONTRACT → STATIC_RECOGNITION → CANONICAL_IR → ARGUMENT_BINDING
  → TARGET_BEHAVIOR → ALLOCATOR → PHYSICAL_MEMORY → BINS → SNAPSHOT
  → CANVAS_TRUTH → RENDERER_PLAN

compare(...) keeps early-stop (first divergence discipline).
diagnose_layers(...) runs ALL layers, reporting per-layer
{semantic_status, evidence_status, missing_required, optional_missing}.
Locked expected_truth files are consumed as-is; the ownership mapping lives
HERE, never by editing truth.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pwn宝"))
from pwnbao.features.heapviz.source_compat import parse_module_source  # noqa: E402

_SEMANTIC_ACTUAL = {
    "alloc": {"alloc", "allocate"},
    "free": {"free", "delete"},
    "edit": {"edit"},
    "show": {"show"},
    "copy": {"copy"},
    "unknown": {"unknown", "init", "value", ""},
}

TIER_RANK = {"name_heuristic": 0, "alias": 1, "interaction_dataflow": 2,
             "binary_source_dataflow": 3}
ACTUAL_SOURCE_TIER = {
    "NAME_CANDIDATE": "name", "SAFE_ALIAS": "alias", "WRAPPER": "alias",
    "STRUCTURAL_BODY": "interaction", "INLINE_ANNOTATION": "interaction",
    "IMPORTED_PROFILE": "interaction", "USER_CONFIRMED": "dataflow_strong",
    "CALLSITE_OUTPUT_FLOW": "interaction",
    "CALLSITE_ARGUMENT_BINDING": "interaction",
}
# EXP-side kinds satisfying HELPER_CONTRACT required_any:
#   interaction -> EXP_PROMPT_SEND_FLOW / EXP_CALLSITE_DATAFLOW
#   alias       -> EXP_WRAPPER_DATAFLOW
EXP_SIDE_KINDS = {"interaction", "alias"}
CONF_ORDER = ["unknown", "candidate", "inferred", "structural", "confirmed"]

_RECV = {"recv", "recvn", "recvline", "recvuntil", "read", "readline", "ru", "rl"}

LAYER_ORDER = ["HELPER_CONTRACT", "STATIC_RECOGNITION", "CANONICAL_IR",
               "ARGUMENT_BINDING", "TARGET_BEHAVIOR", "ALLOCATOR",
               "PHYSICAL_MEMORY", "BINS", "SNAPSHOT", "CANVAS_TRUTH",
               "RENDERER_PLAN"]


# ---------------------------------------------------------------- provenance

def helper_body_output_dataflow(exp_source: str, function: str) -> dict:
    """Independent def-use analysis of OUTPUT_DATA_FLOW (v1.2 §H, P1-3).

    Strong OUTPUT_DATA_FLOW = recv-family result CONSUMED (returned / passed
    as a call argument / arithmetic-compare-parse). Bare assignment whose
    variable is never used is NOT consumption. py2 tolerated."""
    tree, _err = parse_module_source(exp_source or "")
    if tree is None:
        return {"parse_ok": False}
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == function), None)
    if fn is None:
        return {"parse_ok": True, "found": False}
    discarded = {id(p.value) for p in ast.walk(fn)
                 if isinstance(p, ast.Expr) and isinstance(p.value, ast.Call)}
    recv_calls = []
    for c in ast.walk(fn):
        if not isinstance(c, ast.Call):
            continue
        name = c.func.id if isinstance(c.func, ast.Name) else \
            (c.func.attr if isinstance(c.func, ast.Attribute) else "")
        if name in _RECV or name.startswith("recv"):
            recv_calls.append((name, c))
    assigned_vars: dict[str, list[int]] = {}
    for p in ast.walk(fn):
        if isinstance(p, ast.Assign) and isinstance(p.value, ast.Call) and \
                len(p.targets) == 1 and isinstance(p.targets[0], ast.Name):
            for name, c in recv_calls:
                if id(p.value) == id(c):
                    assigned_vars.setdefault(p.targets[0].id, []).append(id(c))
    consumed_var_uses: set[str] = set()
    for p in ast.walk(fn):
        for node in ast.walk(p):
            if isinstance(node, ast.Name) and node.id in assigned_vars:
                if isinstance(p, ast.Return):
                    consumed_var_uses.add(node.id)
                elif isinstance(p, ast.Call) and id(node) != id(p.func) and \
                        not any(id(node) == id(a) for a in ast.walk(p.func)):
                    consumed_var_uses.add(node.id)
                elif isinstance(p, (ast.BinOp, ast.Compare, ast.BoolOp, ast.Subscript)):
                    consumed_var_uses.add(node.id)
    prompt_syncs = weak_assigned = strong = 0
    for name, c in recv_calls:
        if id(c) in discarded:
            if name == "recvuntil":
                prompt_syncs += 1
            continue
        if _is_consumed_directly(fn, c, assigned_vars, consumed_var_uses):
            strong += 1
        else:
            weak_assigned += 1
    return {"parse_ok": True, "found": True, "prompt_syncs": prompt_syncs,
            "weak_assigned_unused": weak_assigned, "output_flows_strong": strong}


def _is_consumed_directly(fn, call, assigned_vars, consumed_var_uses) -> bool:
    for p in ast.walk(fn):
        if isinstance(p, ast.Return) and any(id(n) == id(call) for n in ast.walk(p)):
            return True
        if isinstance(p, ast.Call) and id(p) != id(call) and \
                any(id(n) == id(call) for n in ast.walk(p)):
            return True
        if isinstance(p, (ast.BinOp, ast.Compare, ast.BoolOp)) and \
                any(id(n) == id(call) for n in ast.walk(p)):
            return True
    for var, call_ids in assigned_vars.items():
        if id(call) in call_ids and var in consumed_var_uses:
            return True
    return False


# ---------------------------------------------------------------- ownership

def helper_evidence_requirements(exp_tier: str) -> dict:
    """Evidence Ownership Schema for HELPER_CONTRACT.

    required_any            : EXP-side predicate kind only (the tier floor the
                              analyst's EXP-side evidence supports, capped at
                              interaction: helper contracts never require
                              binary/source evidence).
    optional_corroborating : SOURCE/BINARY flows the analyst happened to have
                              (recorded when missing, never fatal).
    forbidden               : [] (canvas and later layers are simply not
                              consulted here).
    """
    tier = TIER_RANK.get(exp_tier, 2)
    required_any = "interaction" if tier >= TIER_RANK["interaction_dataflow"] \
        else ("alias" if tier >= TIER_RANK["alias"] else "name")
    optional = []
    if tier >= TIER_RANK["binary_source_dataflow"]:
        optional.append("dataflow_strong")  # SOURCE/BINARY_MALLOC_FLOW etc.
    return {"required_any": required_any, "optional_corroborating": optional,
            "forbidden": []}


def target_behavior_evidence_requirements() -> dict:
    return {"required_any": ["SOURCE_INTERNAL_ACTION_FLOW",
                             "BINARY_INTERNAL_ACTION_FLOW"],
            "optional_corroborating": ["EXP_COMMENT_NARRATIVE"],
            "forbidden": []}


def _multimap(items: list, key: str) -> dict:
    """key -> [items] (保序): 同 key 多条目各自保留 —— 禁止
    source_line 单键覆盖 (阶段 1 事件身份)。"""
    out: dict = {}
    for item in items:
        out.setdefault(item.get(key), []).append(item)
    return out


def _normalize_truth(t: dict) -> dict:
    if not any(k in t for k in ("exp_wrapper_truth", "target_behavior_truth",
                                "allocator_truth", "physical_truth")):
        return t
    ew = t.get("exp_wrapper_truth") or {}
    al = t.get("allocator_truth") or {}
    flat = dict(t)
    flat.setdefault("helpers", ew.get("helpers", t.get("helpers", [])))
    flat.setdefault("expected_operations",
                    ew.get("expected_operations", t.get("expected_operations", [])))
    flat.setdefault("allocator_events",
                    al.get("allocator_events", t.get("allocator_events", {})))
    flat.setdefault("machine_checks",
                    al.get("machine_checks", t.get("machine_checks", [])))
    return flat


# ---------------------------------------------------------------- ctx

def _prepare_ctx(expected_truth_raw: dict, actual: dict, exp_source: str,
                 renderer_plan, contract=None):
    """Shared preparation. Returns (run_identity_failure_or_None, ctx)."""
    run_ids = set()

    def collect(obj, where):
        if isinstance(obj, dict) and isinstance(obj.get("run_id"), str):
            run_ids.add((where, obj["run_id"]))

    collect(actual.get("run_manifest"), "run_manifest")
    for key in ("analyzer", "target_behavior", "replay", "physical_memory",
                "canvas_truth_model"):
        collect(actual.get(key), key)
    if renderer_plan:
        collect(renderer_plan, "renderer_plan")
    distinct = {rid for _, rid in run_ids}
    if len(distinct) > 1:
        return {"layer": "RUN_IDENTITY", "step": None, "source_line": None,
                "source_call": None,
                "expected": {"single_authoritative_run": True},
                "actual": {"run_ids": sorted(f"{w}:{r}" for w, r in run_ids)},
                "status_detail": {"layer_detail": "mixed run_id"}}, {}
    truth = _normalize_truth(expected_truth_raw)
    analyzer = actual.get("analyzer") or {}
    canon_all = analyzer.get("canonical_ops", [])
    canon_ops = [o for o in canon_all if o.get("kind") not in ("init", "value")]
    steps = (actual.get("replay") or {}).get("steps") or []
    ctx = {
        "truth": truth,
        "exp_source": exp_source or "",
        "renderer_plan": renderer_plan,
        "analyzer": analyzer,
        "contracts": {c["function"]: c for c in analyzer.get("helper_contracts", [])},
        "canon_all": canon_all,
        "canon_ops": canon_ops,
        "ops_by_line": {o.get("source_line"): o for o in canon_ops},
        "ops_at_line": _multimap(canon_ops, "source_line"),
        "steps": steps,
        "steps_by_op": {s.get("op_id"): s for s in steps if s.get("op_id")},
        "phys_steps": (actual.get("physical_memory") or {}).get("steps") or [],
        "tb_actual": {e.get("op_id"): e
                      for e in (actual.get("target_behavior") or {}).get("per_op", [])},
        "canvas_invariants": actual.get("canvas_invariants") or [],
        "canvas_truth": actual.get("canvas_truth_model") or {},
        "deferred_layers": set(contract.not_applicable_layers) if contract else set(),
    }
    return None, ctx


def compare(expected_truth_raw: dict, actual: dict, exp_source: str = "",
            renderer_plan=None, collect_all: bool = False,
            contract=None) -> dict:
    report = {
        "case_id": expected_truth_raw.get("case_id"),
        "verdict": None,
        "first_divergence": None,
        "helper_contract_status": [],
        "layers_compared": [],
        "layers_not_compared": [],
        "layer_results": [],
        "root_cause": {"component": None, "reason": None},
        "evidence": [],
        "reviewer_reason_hint": None,
        "confidence": None,
    }
    fail, ctx = _prepare_ctx(expected_truth_raw, actual, exp_source,
                             renderer_plan, contract)
    if fail is not None:
        report["verdict"] = "INCONCLUSIVE"
        report["first_divergence"] = fail
        report["reviewer_reason_hint"] = "artifact 混合了不同 run_id, 拒绝比较 (P0-2)"
        return report

    report["_expected_op_count"] = len(ctx["truth"].get("expected_operations", []))
    report["_machine_check_count"] = len(ctx["truth"].get("machine_checks", []))

    divergence = None
    for layer in LAYER_ORDER:
        fn = _LAYERS.get(layer)
        if fn is None:
            report["layers_not_compared"].append(layer)
            report["layer_results"].append(_rec(layer, "SKIPPED"))
            continue
        if layer in ctx.get("deferred_layers", set()):
            report["layers_compared"].append(layer)
            report["layer_results"].append(_rec(
                layer, "DEFERRED",
                detail="评测契约声明本层延迟 (阶段 0.1 NOT_APPLICABLE)"))
            continue
        record, div = fn(ctx, report)
        report["layers_compared"].append(layer)
        report["layer_results"].append(record)
        if div is not None:
            # first divergence wins — collect_all keeps scanning but never
            # replaces the earliest divergence
            if divergence is None:
                divergence = div
            if not collect_all:
                break
    if divergence is not None:
        report["verdict"] = "DIVERGED"
        fd = dict(divergence)
        report["root_cause"]["component"] = fd.pop("_component", None)
        report["evidence"] = fd.pop("_evidence", [])
        report["reviewer_reason_hint"] = fd.pop("_hint", None)
        report["first_divergence"] = fd
    else:
        report["verdict"] = "MATCH"
    return report


def diagnose_layers(expected_truth_raw: dict, actual: dict, exp_source: str = "",
                    renderer_plan=None) -> dict:
    """Full-layer diagnostic (no early stop). verdict/first_divergence still
    follow early-stop semantics; layer_results carries every layer."""
    report = compare(expected_truth_raw, actual, exp_source, renderer_plan,
                     collect_all=True)
    report["diagnostic_mode"] = True
    return report


# ---------------------------------------------------------------- records

def _rec(layer, status, semantic=None, evidence=None, missing_required=None,
         optional_missing=None, detail=None):
    return {"layer": layer, "status": status,
            "semantic_status": semantic if semantic is not None else status,
            "evidence_status": evidence or "",
            "missing_required": missing_required or [],
            "optional_missing": optional_missing or [],
            "detail": detail or ""}


def _div(layer, line, call, expected, actual, component, evidence, hint,
         step=None):
    return {"layer": layer, "step": step, "source_line": line,
            "source_call": call, "expected": expected, "actual": actual,
            "_component": component, "_evidence": evidence, "_hint": hint}


# ---------------------------------------------------------------- layers

def _l_helper_contract(ctx, report):
    L = "HELPER_CONTRACT"
    records = []
    optional_missing_all = set()
    for h in ctx["truth"].get("helpers", []):
        fn = h["function"]
        exp_sem = h.get("semantic", "unknown")
        act = ctx["contracts"].get(fn)
        status = {"helper": fn, "expected_semantic": exp_sem}
        if act is None:
            status["semantic"] = "SEMANTIC_DIVERGED"
            records.append(status)
            report["helper_contract_status"] = records
            return _rec(L, "DIVERGED", semantic="SEMANTIC_DIVERGED",
                        detail=f"{fn} 无契约"), _div(
                L, h.get("_line"), f"def {fn}()",
                {"semantic": exp_sem, "roles": h.get("roles")},
                {"contract": None}, "HelperContractResolver",
                h.get("evidence", []), f"helper {fn} 无契约")
        act_op = act.get("operation")

        # (1) semantic
        if not _matches(exp_sem, act_op):
            status.update({"semantic": "SEMANTIC_DIVERGED",
                           "actual_operation": act_op,
                           "divergence_field": "semantic"})
            records.append(status)
            report["helper_contract_status"] = records
            return _rec(L, "DIVERGED", semantic="SEMANTIC_DIVERGED",
                        detail=f"{fn}: {act_op} ≠ {exp_sem}"), _div(
                L, h.get("_line"), f"def {fn}()",
                {"semantic": exp_sem, "roles": h.get("roles"),
                 "helper_evidence": h.get("evidence")},
                {"operation": act_op, "confidence": act.get("confidence"),
                 "evidence": act.get("evidence")},
                "HelperContractResolver", h.get("evidence", []),
                f"{fn} 语义判定 {act_op}, 证据支持 {exp_sem}")
        status["actual_operation"] = act_op

        # (2) argument_roles
        act_roles = act.get("roles") or {}
        pos_role = {b.get("position"): r for r, b in act_roles.items()
                    if isinstance(b, dict) and isinstance(b.get("position"), int)
                    and b["position"] >= 0}
        for arg_key, exp_role in sorted(h.get("roles", {}).items(),
                                        key=lambda kv: int(kv[0][3:]) if kv[0].startswith("arg") else 99):
            if exp_role in (None, "unknown", "null") or str(exp_role).startswith("unknown_"):
                continue
            pos = int(arg_key[3:]) if arg_key.startswith("arg") else None
            if pos_role.get(pos) != exp_role:
                status.update({"semantic": "SEMANTIC_DIVERGED",
                               "divergence_field": "argument_roles"})
                records.append(status)
                report["helper_contract_status"] = records
                return _rec(L, "DIVERGED", semantic="SEMANTIC_DIVERGED",
                            detail=f"{fn}.{arg_key} role"), _div(
                    L, h.get("_line"), f"def {fn}(): {arg_key}",
                    {"role": exp_role, "position": pos}, {"bindings": act_roles},
                    "HelperContractResolver (argument binding)",
                    h.get("evidence", []),
                    f"{fn} {arg_key} 期望 {exp_role}, 实际 {pos_role.get(pos)}")

        # (3-6) evidence ownership: ONLY EXP-side predicates are required.
        reqs = helper_evidence_requirements(h.get("evidence_tier",
                                                   "interaction_dataflow"))
        act_sources = act.get("evidence_sources") or []
        actual_kinds = {ACTUAL_SOURCE_TIER.get(s, "name") for s in act_sources}
        missing_required = []
        if reqs["required_any"] not in actual_kinds and \
                not (actual_kinds & EXP_SIDE_KINDS):
            missing_required.append(
                f"EXP-side evidence (required_any={reqs['required_any']})")
        optional_missing = [f"BINARY/SOURCE corroboration ({k})"
                            for k in reqs["optional_corroborating"]
                            if k not in actual_kinds]
        optional_missing_all.update(optional_missing)
        # confidence floor stays (part of the analyst's requirement strength)
        act_conf = act.get("confidence") or "unknown"
        exp_conf = float(h.get("confidence") or 0.0)
        required_conf_class = "structural" if exp_conf >= 0.9 else \
            ("inferred" if exp_conf >= 0.8 else "candidate")
        conf_short = CONF_ORDER.index(act_conf) < CONF_ORDER.index(required_conf_class)
        # (6) provenance: SHOW must not rest on fabricated structural evidence
        prov = helper_body_output_dataflow(ctx["exp_source"], fn) \
            if ctx["exp_source"] else {"parse_ok": None}
        unsound = None
        if "STRUCTURAL_BODY" in act_sources and prov.get("found") \
                and exp_sem == "show" and not prov.get("output_flows_strong"):
            unsound = (f"{fn} 体内无强 OUTPUT_DATA_FLOW (def-use: "
                       f"prompt_syncs={prov.get('prompt_syncs')}, "
                       f"strong={prov.get('output_flows_strong')}, "
                       f"weak_assigned_unused={prov.get('weak_assigned_unused')}), "
                       f"但契约以 STRUCTURAL_BODY 判 show")
        if missing_required or conf_short or unsound:
            status.update({"semantic": "SEMANTIC_MATCH",
                           "evidence": "EVIDENCE_DIVERGED",
                           "divergence_field": ("provenance" if unsound else
                                                "confidence" if conf_short else
                                                "evidence_predicates"),
                           "actual_evidence_sources": act_sources,
                           "actual_confidence": act_conf,
                           "provenance_recheck": prov if unsound else None})
            records.append(status)
            report["helper_contract_status"] = records
            return _rec(L, "EVIDENCE_DIVERGED", semantic="SEMANTIC_MATCH",
                        evidence="EVIDENCE_DIVERGED",
                        missing_required=missing_required,
                        optional_missing=optional_missing,
                        detail=unsound or f"{fn}: 缺 {missing_required} (conf {act_conf}<{required_conf_class})"), _div(
                L, h.get("_line"), f"def {fn}()",
                {"semantic": exp_sem,
                 "required_any": "EXP-side evidence",
                 "optional_corroborating": reqs["optional_corroborating"],
                 "confidence_requirement": required_conf_class},
                {"operation": act_op, "evidence_sources": act_sources,
                 "confidence": act_conf,
                 "provenance_recheck": prov if unsound else None},
                "HelperContractResolver (EXP evidence ownership)",
                h.get("evidence", []),
                unsound or f"{fn} 缺少 EXP 侧证据 {missing_required} 或置信不足 "
                           f"({act_conf} < {required_conf_class})")
        status.update({"semantic": "MATCH", "evidence": "MATCH",
                       "optional_missing": optional_missing,
                       "actual_evidence_sources": act_sources})
        records.append(status)
    report["helper_contract_status"] = records
    return _rec(L, "MATCH", semantic="MATCH", evidence="MATCH",
                optional_missing=sorted(optional_missing_all),
                detail=f"{len(records)} helpers"), None


def _l_static_recognition(ctx, report):
    L = "STATIC_RECOGNITION"
    for e in ctx["truth"].get("expected_operations", []):
        if e.get("source_line") not in ctx["ops_by_line"]:
            return _rec(L, "DIVERGED",
                        detail=f"L{e.get('source_line')} 未识别"), _div(
                L, e.get("source_line"), e.get("source_call"),
                {"recognized": True, "kind": e.get("kind")},
                {"heap_ops_lines": sorted(ctx["ops_by_line"].keys())},
                "HeapSourceAnalyzer recognition", e.get("evidence", []),
                f"调用点 {e.get('source_line')} 未被识别")
    return _rec(L, "MATCH"), None


def _l_canonical_ir(ctx, report):
    L = "CANONICAL_IR"
    for e in ctx["truth"].get("expected_operations", []):
        o = ctx["ops_by_line"].get(e.get("source_line"))
        if o and not _matches(e.get("kind", "unknown"), o.get("kind")):
            return _rec(L, "DIVERGED",
                        detail=f"L{e['source_line']} kind"), _div(
                L, e["source_line"], e.get("source_call"),
                {"kind": e.get("kind")},
                {"kind": o.get("kind"), "op_id": o.get("op_id")},
                "Canonical IR conversion", e.get("evidence", []),
                f"L{e['source_line']} kind={o.get('kind')}, 期望 {e.get('kind')}")
    return _rec(L, "MATCH"), None


def _l_argument_binding(ctx, report):
    L = "ARGUMENT_BINDING"
    for e in ctx["truth"].get("expected_operations", []):
        if e.get("kind") == "alloc":
            continue
        o = ctx["ops_by_line"].get(e.get("source_line"))
        if not o:
            continue
        av = _concrete(o.get("handle"))
        exp_idx = (e.get("arguments") or {}).get("arg0")
        if isinstance(exp_idx, str) and exp_idx.startswith("0x"):
            try:
                exp_idx = int(exp_idx, 16)
            except ValueError:
                exp_idx = None
        if isinstance(exp_idx, int) and av is not None and av != exp_idx:
            return _rec(L, "DIVERGED", detail=f"L{e['source_line']} handle"), _div(
                L, e["source_line"], e.get("source_call"),
                {"handle": exp_idx}, {"handle": av, "op_id": o.get("op_id")},
                "argument binding → IR handle", e.get("evidence", []),
                f"L{e['source_line']} 槽位 {av}, 期望 {exp_idx}")
    return _rec(L, "MATCH"), None


def _l_target_behavior(ctx, report):
    L = "TARGET_BEHAVIOR"
    reqs = target_behavior_evidence_requirements()
    for spec in (ctx["truth"].get("allocator_events") or {}).get("per_call") or []:
        line = spec.get("source_line")
        # 聚合该行全部 canonical ops 的动作 (1:N 展开后同线多 op)
        line_ops = ctx["ops_at_line"].get(line) or []
        if not line_ops:
            continue
        act_actions = []
        not_modeled_any = False
        for o in line_ops:
            entry = ctx["tb_actual"].get(o.get("op_id")) or {}
            act_actions.extend(entry.get("actions") or [])
            if entry.get("internals_not_modeled"):
                not_modeled_any = True
        exp_counts, act_counts = {}, {}
        for ev in spec.get("events") or []:
            exp_counts[ev.get("kind")] = exp_counts.get(ev.get("kind"), 0) + 1
        for ev in act_actions:
            act_counts[ev.get("action")] = act_counts.get(ev.get("action"), 0) + 1
        if exp_counts != act_counts:
            return (_rec(
                L, "DIVERGED",
                semantic=("DIVERGED (target internals not modeled)"
                          if not_modeled_any else "DIVERGED"),
                evidence="REQUIRED_MISSING",
                missing_required=list(reqs["required_any"]) if not_modeled_any else [],
                optional_missing=[],
                detail=f"L{line} {spec.get('call')}: 期望 {exp_counts}, 管线推导 {act_counts}"),
                _div(
                L, line, spec.get("call"),
                {"actions": exp_counts,
                 "note": "expected target-behavior actions (binary/source truth)"},
                {"actions": act_counts,
                 "internals_not_modeled": not_modeled_any,
                 "derivation": (ctx["tb_actual"].get(
                     line_ops[0].get("op_id")) or {}).get("derivation") if line_ops else ""},
                "TargetBehavior stage",
                [ev for e in spec.get("events") or [] for ev in e.get("evidence", [])],
                f"L{line} {spec.get('call')}: 期望 {exp_counts}, 当前管线推导 "
                f"{act_counts}" + (" (内部动作未建模, SOURCE/BINARY "
                                   "internal-action flow 证据缺席)"
                                   if not_modeled_any else "")))
    return _rec(L, "MATCH"), None


def _l_allocator(ctx, report):
    L = "ALLOCATOR"
    for entry in (ctx["tb_actual"] or {}).values():
        op_id = entry.get("op_id")
        st = ctx["steps_by_op"].get(op_id)
        if st is None:
            continue
        mallocs = [a for a in entry.get("actions") or [] if a.get("action") == "malloc"]
        frees = [a for a in entry.get("actions") or [] if a.get("action") == "free"]
        act_allocs = st.get("alloc_events") or []
        act_frees = st.get("free_events") or []
        if len(mallocs) != len(act_allocs):
            return _rec(L, "DIVERGED", detail=f"op {op_id} malloc count"), _div(
                L, entry.get("source_line"), None,
                {"malloc_action_count": len(mallocs)},
                {"alloc_event_count": len(act_allocs), "op_id": op_id},
                "GlibcHeapEngine malloc conversion", [],
                f"op {op_id}: {len(mallocs)} 个 malloc 动作产生 {len(act_allocs)} 个事件")
        if len(frees) != len(act_frees):
            return _rec(L, "DIVERGED", detail=f"op {op_id} free count"), _div(
                L, entry.get("source_line"), None,
                {"free_action_count": len(frees)},
                {"free_event_count": len(act_frees), "op_id": op_id},
                "GlibcHeapEngine free conversion", [],
                f"op {op_id}: {len(frees)} 个 free 动作产生 {len(act_frees)} 个事件")
        for act, ev in zip(mallocs, act_allocs):
            req = _concrete(act.get("request"))
            ev_req = _int_hex(ev.get("request_size"))
            if req is not None and ev_req is not None and req != ev_req:
                return _rec(L, "DIVERGED", detail=f"op {op_id} request"), _div(
                    L, entry.get("source_line"), None,
                    {"malloc_request": req},
                    {"event_request": ev_req, "op_id": op_id},
                    "GlibcHeapEngine request conversion", [],
                    f"op {op_id}: malloc({req}) 事件请求 {ev_req}")
    return _rec(L, "MATCH"), None


def _l_physical_memory(ctx, report):
    L = "PHYSICAL_MEMORY"
    for st in ctx["steps"]:
        op_id = st.get("op_id")
        ps = next((p for p in ctx["phys_steps"] if p.get("op_id") == op_id), None)
        if ps is None:
            continue
        # 语义检查: 每个逻辑 chunk 都必须有物理 backing (一对多 alias 合法)
        logical_backings = {c.get("physical_id") for c in
                            (ps.get("stale_separated_views") or {}).get("logical_chunks", [])
                            if isinstance(c, dict) and c.get("physical_id")}
        physical_ids = {c.get("physical_id") for c in ps.get("physical_objects") or []}
        missing = {pid for pid in logical_backings if pid and pid not in physical_ids}
        if missing:
            return (_rec(L, "DIVERGED", detail=f"op {op_id} missing backing"), _div(
                L, None, None,
                {"logical_chunks_need_backing": sorted(missing)},
                {"physical_objects": sorted(physical_ids)[:10], "op_id": op_id},
                "PhysicalMemory backing", [],
                f"op {op_id}: 逻辑 chunk 无物理 backing: {sorted(missing)[:5]}"))
    return _rec(L, "MATCH"), None


def _l_bins(ctx, report):
    L = "BINS"
    for chk in ctx["truth"].get("machine_checks") or []:
        o = ctx["ops_by_line"].get(chk.get("after_line"))
        if not o:
            continue
        st = ctx["steps_by_op"].get(o.get("op_id"))
        if st is None:
            continue
        ok, observed = _bin_check(chk, st)
        if not ok:
            return _rec(L, "DIVERGED",
                        detail=f"L{chk.get('after_line')} {chk.get('check')}"), _div(
                L, chk.get("after_line"), None,
                {"check": chk.get("check"), "fact": chk.get("fact"),
                 "value": chk.get("value")},
                {"observed": observed, "op_id": o.get("op_id")},
                "GlibcHeapEngine bins", chk.get("evidence", []),
                f"L{chk.get('after_line')} 后 {chk.get('fact')} (op {o.get('op_id')})")
    return _rec(L, "MATCH"), None


def _l_snapshot(ctx, report):
    L = "SNAPSHOT"
    canon_ids = {o.get("op_id") for o in ctx["canon_all"]}
    orphan = [s.get("op_id") for s in ctx["steps"]
              if s.get("op_id") not in canon_ids and s.get("op_id") != "initial"]
    if orphan:
        return _rec(L, "DIVERGED", detail="orphan steps"), _div(
            L, None, None, {"steps_map_to_canonical_ops": True},
            {"orphan_op_ids": orphan[:5]},
            "Snapshot ↔ CanonicalOp identity", [],
            f"snapshot 存在无 canonical 对应的 op_id: {orphan[:5]}")
    return _rec(L, "MATCH"), None


def _l_canvas_truth(ctx, report):
    L = "CANVAS_TRUTH"
    bad = [r for r in ctx["canvas_invariants"] if r.get("violations")]
    if bad:
        b = bad[0]
        v = b["violations"][0]
        return _rec(L, "DIVERGED",
                    detail=f"step {b.get('step')} inv{v['invariant']}"), _div(
            L, None, None, {"invariant": v["invariant"], "holds": True},
            {"step": b.get("step"), "op_id": b.get("op_id"), "violation": v},
            "canvas_model.py CanvasTruthModel",
            [f"step {b.get('step')} inv{v['invariant']}: {v['what']}"],
            f"canvas invariant {v['invariant']} 违规 @step {b.get('step')}")
    return _rec(L, "MATCH"), None


def _l_renderer_plan(ctx, report):
    L = "RENDERER_PLAN"
    if not ctx["renderer_plan"]:
        return _rec(L, "SKIPPED", detail="plan artifact not provided"), None
    fail = _compare_truth_vs_plan(ctx["canvas_truth"], ctx["renderer_plan"])
    if fail:
        return _rec(L, "DIVERGED", detail=fail.get("hint")), _div(
            L, None, None, fail["expected"], fail["actual"],
            "JS renderer plan vs CanvasTruthModel", [], fail["hint"])
    return _rec(L, "MATCH"), None


_LAYERS = {
    "HELPER_CONTRACT": _l_helper_contract,
    "STATIC_RECOGNITION": _l_static_recognition,
    "CANONICAL_IR": _l_canonical_ir,
    "ARGUMENT_BINDING": _l_argument_binding,
    "TARGET_BEHAVIOR": _l_target_behavior,
    "ALLOCATOR": _l_allocator,
    "PHYSICAL_MEMORY": _l_physical_memory,
    "BINS": _l_bins,
    "SNAPSHOT": _l_snapshot,
    "CANVAS_TRUTH": _l_canvas_truth,
    "RENDERER_PLAN": _l_renderer_plan,
}


# ---------------------------------------------------------------- plan checks

def _compare_truth_vs_plan(truth: dict, plan: dict) -> dict | None:
    """Five special checks (P0-5), calibrated to the REAL JS conventions."""
    truth_steps = {t.get("step"): t for t in truth.get("steps") or []}
    for ps in plan.get("steps") or []:
        t = truth_steps.get(ps.get("step"))
        if not t:
            continue
        word = 8
        t_header_bytes = sum(r["physical_end"] - r["physical_start"]
                             for r in t.get("rows") or []
                             if r.get("kind") in ("prev_size", "size"))
        p_header_bytes = sum(2 * word for c in ps.get("cards") or []
                             if any(r.get("kind") == "header"
                                    for r in (c.get("rows") or [])))
        if t_header_bytes and t_header_bytes != p_header_bytes:
            return {"expected": {"header_byte_coverage": t_header_bytes},
                    "actual": {"header_byte_coverage": p_header_bytes,
                               "js_convention": "single prev_size|size row"},
                    "hint": "header 行字节覆盖不一致"}
        for card in ps.get("cards") or []:
            tc = next((c for c in t.get("chunks") or []
                       if c.get("physical_id") == card.get("physical_id")), None)
            if tc and card.get("geometry_basis") != "physical_extent_size":
                return {"expected": {"geometry_basis": "physical_extent_size",
                                     "physical_id": card.get("physical_id")},
                        "actual": {"geometry_basis": card.get("geometry_basis")},
                        "hint": "renderer plan 行几何未以 physical_extent_size 为基"}
        truth_ov = {}
        for sp in (t.get("paint_spans") or {}).get("physical_overlap") or []:
            truth_ov.setdefault(sp.get("owner"), []).append((sp.get("start"), sp.get("end")))
        for card in ps.get("cards") or []:
            plan_ov = sorted((sp.get("start"), sp.get("end"))
                             for sp in (card.get("spans") or {}).get("overlap") or [])
            tov = sorted(x for x in truth_ov.get(card.get("physical_id"), [])
                         if x[0] is not None and x[1] is not None)
            if plan_ov != tov:
                return {"expected": {"overlap_spans": tov,
                                     "physical_id": card.get("physical_id")},
                        "actual": {"overlap_spans": plan_ov},
                        "hint": "physical_overlap 字节区间不一致"}
        user_rows = {}
        for r in t.get("rows") or []:
            if r.get("kind") == "user":
                user_rows[r["physical_id"]] = user_rows.get(r["physical_id"], 0) + 1
        for card in ps.get("cards") or []:
            n = user_rows.get(card.get("physical_id"))
            if n is None:
                continue
            if n > 4096 and not card.get("virtualized"):
                return {"expected": {"virtualized": True, "user_rows": n},
                        "actual": {"virtualized": card.get("virtualized")},
                        "hint": "超过两种 regime 阈值却未 virtualize"}
            if n <= 6 and card.get("virtualized"):
                return {"expected": {"virtualized": False, "user_rows": n},
                        "actual": {"virtualized": card.get("virtualized")},
                        "hint": "低于两种 regime 阈值却 virtualize"}
        if (t.get("top_chunk") or {}).get("offset") is not None and not ps.get("top_card"):
            return {"expected": {"top_card": True}, "actual": {"top_card": None},
                    "hint": "truth 有 top chunk 但 renderer plan 无 top card 几何"}
    return None


# ---------------------------------------------------------------- misc

def _bin_check(chk, st) -> tuple[bool, str]:
    kind = chk.get("check")
    if kind == "live_chunks":
        return st.get("n_chunks") == chk.get("value"), f"n_chunks={st.get('n_chunks')}"
    if kind in ("bin_nonempty", "bin_empty"):
        bins = st.get(chk.get("bin") or "fastbins") or {}
        sc = chk.get("size_class")
        if isinstance(bins, dict):
            if sc:
                lst = bins.get(sc) or bins.get(str(sc).replace("0x", "")) or []
                n = len(lst) if isinstance(lst, list) else (1 if lst else 0)
            else:
                n = sum(len(v) for v in bins.values() if isinstance(v, list))
        else:
            n = len(bins) if isinstance(bins, list) else 0
        ok = (n > 0) if kind == "bin_nonempty" else (n == 0)
        return ok, f"{chk.get('bin')}={bins}"
    return True, ""


def _int_hex(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip(), 0)
    except (ValueError, TypeError):
        return None


def _concrete(av):
    if isinstance(av, dict) and av.get("kind") == "concrete":
        for k, v in av.items():
            if k not in ("kind", "source"):
                return v
    return None


def _matches(semantic, actual_op):
    return (actual_op or "unknown") in _SEMANTIC_ACTUAL.get(semantic, {semantic})
