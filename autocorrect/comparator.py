#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""First-divergence comparator.

Layer order (upstream first):
  helper_contract -> ir -> allocator -> (canvas_renderer, future)

Discipline: report ONLY the first diverging layer; downstream breakage is
listed as downstream_effects. A mismatch the reviewer cannot prove on its own
side must be resolved against the expected analysis, not silently accepted.
"""
from __future__ import annotations

import json
from pathlib import Path

# expected operation <-> PwnCraft CanonicalOperationKind
_OP_MAP = {
    "alloc": {"alloc", "allocate"},
    "free": {"free", "delete"},
    "edit": {"edit"},
    "show": {"show"},
    "copy": {"copy"},
    "unknown": {"unknown", "init", "value", ""},
}

_LAYER_ORDER = ["helper_contract", "ir", "allocator"]


def _op_matches(expected_op: str, actual_op: str) -> bool:
    exp = _OP_MAP.get(expected_op, {expected_op})
    return (actual_op or "unknown") in exp


def _concrete(av: dict | None):
    if isinstance(av, dict) and av.get("kind") == "concrete":
        for k, v in av.items():
            if k not in ("kind", "source"):
                return v
    return None


def compare(expected: dict, actual: dict) -> dict:
    """Returns a DivergenceReport-shaped dict (verdict MATCH/DIVERGED/INCONCLUSIVE)."""
    report = {
        "case_id": expected.get("case_id"),
        "compared_artifacts": {
            "expected_analysis": expected.get("_path"),
            "pwncraft_output": actual.get("_path"),
            "pwncraft_recognizer_revision": (actual.get("analyzer") or {}).get("recognizer_revision"),
        },
    }

    # ---------------- layer 1: helper_contract
    expected_helpers = {h["function"]: h for h in expected.get("helpers", [])}
    actual_contracts = {c["function"]: c for c in (actual.get("analyzer") or {}).get("helper_contracts", [])}
    # compare in expected program order
    for h in expected.get("helpers", []):
        fn = h["function"]
        act = actual_contracts.get(fn)
        exp_op = h.get("operation", "unknown")
        act_op = (act or {}).get("operation", "<missing>")
        if act is None:
            report["verdict"] = "DIVERGED"
            report["first_divergence"] = {
                "layer": "helper_contract",
                "location": {"file": h.get("_file", "exp.py"), "line": h.get("source_line"),
                             "call": f"def {fn}(...)"},
                "pwncraft_output": {"helper_contract": None},
                "expected": {"function": fn, "operation": exp_op},
                "downstream_effects": [
                    "该 helper 的所有调用点在 IR/allocator 层缺乏契约支撑",
                ],
            }
            report["root_cause"] = (
                f"helper {fn} 未被 PwnCraft 解析出契约 (contract 缺失)"
            )
            report["evidence"] = h.get("operation_evidence", [])
            return report
        if not _op_matches(exp_op, act_op):
            report["verdict"] = "DIVERGED"
            report["first_divergence"] = {
                "layer": "helper_contract",
                "location": {"file": h.get("_file", "exp.py"), "line": h.get("source_line"),
                             "call": f"def {fn}(...)"},
                "pwncraft_output": {"operation": act_op,
                                    "confidence": act.get("confidence"),
                                    "evidence_sources": act.get("evidence_sources"),
                                    "roles": act.get("roles")},
                "expected": {"operation": exp_op,
                             "operation_evidence": h.get("operation_evidence", [])},
                "downstream_effects": _downstream_for_op(exp_op, act_op),
            }
            report["root_cause"] = (
                f"helper {fn} 的 operation 判定错误: PwnCraft={act_op}, 证据支持 {exp_op}"
            )
            report["evidence"] = h.get("operation_evidence", [])
            return report
        # parameter roles
        expected_roles = {p["role"]: p for p in h.get("parameters", []) if p.get("role") not in (None, "unknown")}
        actual_roles = {r: b for r, b in (act.get("roles") or {}).items()}
        for role, p in expected_roles.items():
            b = actual_roles.get(role)
            if b is None or (b.get("parameter") not in (None, "") and b.get("parameter") != p.get("name")):
                report["verdict"] = "DIVERGED"
                report["first_divergence"] = {
                    "layer": "helper_contract",
                    "location": {"file": h.get("_file", "exp.py"), "line": h.get("source_line"),
                                 "call": f"def {fn}(...): param {p.get('name')}"},
                    "pwncraft_output": {"role_binding": b,
                                        "all_roles": actual_roles},
                    "expected": {"role": role, "parameter": p.get("name"),
                                 "position": p.get("position"),
                                 "evidence": p.get("evidence", [])},
                    "downstream_effects": [
                        f"{fn}() 的 {role} 实参无法流入 Canonical IR 的对应槽位 "
                        "(handle/allocator_request/payload), 下游 chunk 映射与画布随之失真",
                    ],
                }
                report["root_cause"] = (
                    f"{fn}() 形参 {p.get('name')} 的 {role} 角色未被绑定; "
                    "缺少 prompt-label / data-flow 级参数角色推断"
                )
                report["evidence"] = p.get("evidence", [])
                return report

    # ---------------- layer 2: ir sequence
    trace = expected.get("call_trace", [])
    ops = [o for o in (actual.get("analyzer") or {}).get("canonical_ops", [])
           if o.get("kind") not in ("init", "value")]
    if trace:
        if len(ops) != len(trace):
            report["verdict"] = "DIVERGED"
            report["first_divergence"] = {
                "layer": "ir",
                "location": {"file": "exp.py", "line": None, "call": None},
                "pwncraft_output": {"heap_op_count": len(ops)},
                "expected": {"heap_op_count": len(trace)},
                "downstream_effects": ["操作序列长度不一致, 快照对齐失效"],
            }
            report["root_cause"] = "IR 展开的操作数与 EXP 主流程 helper 调用数不一致"
            report["evidence"] = [
                f"expected call_trace seq={len(trace)} vs pwncraft heap ops={len(ops)}"]
            return report
        for t, o in zip(trace, ops):
            exp_op = expected_helpers.get(t["helper"], {}).get("operation", "unknown")
            if not _op_matches(exp_op, o.get("kind")):
                report["verdict"] = "DIVERGED"
                report["first_divergence"] = {
                    "layer": "ir",
                    "location": {"file": "exp.py", "line": o.get("source_line"),
                                 "call": o.get("source_call")},
                    "pwncraft_output": {"seq": t["seq"], "kind": o.get("kind"),
                                        "handle": o.get("handle")},
                    "expected": {"seq": t["seq"], "helper": t["helper"],
                                 "operation": exp_op, "args": t.get("args")},
                    "downstream_effects": ["后续所有 snapshot 的 bins/chunks 状态与真实语义脱节"],
                }
                report["root_cause"] = (
                    f"seq {t['seq']}: helper {t['helper']} 的调用被识别为 {o.get('kind')} "
                    f"而非 {exp_op} (contract 层误判的传播)"
                )
                report["evidence"] = expected_helpers.get(t["helper"], {}).get("operation_evidence", [])
                return report
            exp_handle = t.get("args", [None])[0] if exp_op != "alloc" else None
            if exp_op == "alloc":
                continue  # alloc 的 index 由模拟器按分配序推导, 单独在 allocator 层校验
            av = _concrete(o.get("handle"))
            if isinstance(exp_handle, int) and av is not None and av != exp_handle:
                report["verdict"] = "DIVERGED"
                report["first_divergence"] = {
                    "layer": "ir",
                    "location": {"file": "exp.py", "line": o.get("source_line"),
                                 "call": o.get("source_call")},
                    "pwncraft_output": {"seq": t["seq"], "handle": av},
                    "expected": {"seq": t["seq"], "handle": exp_handle},
                    "downstream_effects": ["操作作用在错误的 chunk 槽位上"],
                }
                report["root_cause"] = f"seq {t['seq']}: index 实参推导错误"
                report["evidence"] = [f"call {t}.index 应为 {exp_handle}"]
                return report

    # ---------------- layer 3: allocator (machine checks)
    trace = trace or expected.get("call_trace", [])
    ops = [o for o in (actual.get("analyzer") or {}).get("canonical_ops", [])
           if o.get("kind") not in ("init", "value")]
    seq_to_step = {t["seq"]: o.get("step") for t, o in zip(trace, ops)}
    failed_checks = _run_machine_checks(expected.get("machine_checks", []),
                                        actual.get("replay") or {}, seq_to_step, trace)
    if failed_checks:
        fc = failed_checks[0]
        report["verdict"] = "DIVERGED"
        report["first_divergence"] = fc["divergence"]
        report["root_cause"] = fc["root_cause"]
        report["evidence"] = fc["evidence"]
        return report

    if report.get("verdict") is None:
        report["verdict"] = "MATCH"
    return report


def _downstream_for_op(expected_op: str, actual_op: str) -> list:
    effects = []
    if expected_op == "free" and actual_op not in ("free", "delete"):
        effects = [
            "引擎不会释放任何 chunk: fastbin/tcache/unsorted 全程为空",
            "后续 allocate 的槽位推导退化为单调递增, 而非复用被释放槽位",
            "fastbin/dup/poisoning 类利用链在画布上不可见",
        ]
    elif expected_op == "alloc" and actual_op not in ("alloc", "allocate"):
        effects = ["分配缺失: chunk 数量/地址推导与真实布局不符"]
    elif expected_op == "edit" and actual_op != "edit":
        effects = ["写入缺失: overflow/UAF 写在画布上不可见"]
    elif expected_op == "show" and actual_op != "show":
        effects = ["泄露缺失: libc/heap 地址泄露链不可见"]
    effects.append(f"contract 层误判向 IR/allocator/画布逐层传播")
    return effects


def _run_machine_checks(checks: list, replay: dict, seq_to_step: dict, trace: list) -> list:
    """checks: [{'after_seq': n, 'check': kind, 'value': x, ...}]. Returns failures."""
    failures = []
    steps = replay.get("steps") or []
    by_step = {s.get("step"): s for s in steps if isinstance(s, dict)}
    for chk in checks or []:
        after = chk.get("after_seq")
        step_id = seq_to_step.get(after)
        if step_id is None or step_id not in by_step:
            continue  # cannot check -> INCONCLUSIVE territory, not a divergence
        st = by_step[step_id]
        kind = chk.get("check")
        ok, detail, cause = False, "", ""
        if kind == "live_chunks":
            ok = st.get("n_chunks") == chk["value"]
            detail = f"n_chunks={st.get('n_chunks')} expected={chk['value']}"
            cause = "存活 chunk 计数与预期不符"
        elif kind == "fastbin_empty":
            fb = st.get("fastbins") or {}
            total = sum(len(v) for v in fb.values()) if isinstance(fb, dict) else 0
            ok = total == 0
            detail = f"fastbins={fb} expected_empty={chk['value']}"
            cause = "fastbin 状态与预期不符"
        elif kind == "fastbin_nonempty":
            fb = st.get("fastbins") or {}
            total = sum(len(v) for v in fb.values()) if isinstance(fb, dict) else 0
            ok = total > 0
            detail = f"fastbins={fb} expected_nonempty={chk['value']}"
            cause = "fastbin 应有被释放 chunk 但为空 (free 语义未生效)"
        elif kind == "unsorted_nonempty":
            us = st.get("unsorted") or {}
            total = sum(len(v) for v in us.values()) if isinstance(us, dict) else 0
            ok = total > 0
            detail = f"unsorted={us} expected_nonempty={chk['value']}"
            cause = "unsorted bin 应含 chunk 但为空 (free 语义未生效)"
        else:
            continue  # unknown check kind: skip, don't fail
        if not ok:
            failures.append({
                "divergence": {
                    "layer": "allocator",
                    "location": {"file": "exp.py",
                                 "line": _trace_line(after, trace), "call": None},
                    "pwncraft_output": {"step": st.get("step"), "observed": detail},
                    "expected": {"after_seq": after, "check": kind, "value": chk.get("value"),
                                 "fact": chk.get("fact")},
                    "downstream_effects": ["画布 bins/布局与真实堆状态不符"],
                },
                "root_cause": f"after_seq {after}: {cause}",
                "evidence": chk.get("evidence", []),
            })
    return failures


def _trace_line(seq, trace):
    for t in trace or []:
        if t.get("seq") == seq:
            return t.get("source_line")
    return None
