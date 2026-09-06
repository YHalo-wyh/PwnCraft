#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M5 资源基线 + 封存评测辅助 (VNext M5)。

- resource_baseline: 对 GOLD/SILVER 案例的 audit + analyze 计时 (p50/p95)
- assign_splits: 按来源簇稳定划分 60/20/20 (hash of source repo+path),
  训练/迁移验证/封存 三集合写入 splits.json
Deterministic-First: 划分由 sha 决定, 与运行顺序无关。
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

SPLIT_RATIOS = {"train": 0.6, "validation": 0.2, "frozen_test": 0.2}


def _cluster_of(case: dict) -> str:
    src = (case.get("source") or {})
    return f"{src.get('repository_url', '')}|{src.get('challenge_path', '')}"


def _stable_bucket(text: str, ratios: dict[str, float]) -> str:
    digest = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:16], 16)
    r = digest / 0xFFFFFFFFFFFFFFFF
    acc = 0.0
    for name, ratio in ratios.items():
        acc += ratio
        if r < acc:
            return name
    return list(ratios)[-1]


def assign_splits(manifests: list[dict], ratios: dict[str, float] | None = None) -> dict:
    ratios = ratios or SPLIT_RATIOS
    splits: dict[str, list] = {k: [] for k in ratios}
    for case in manifests:
        cluster = _cluster_of(case)
        split = _stable_bucket(cluster + "|" + str(case.get("case_id")), ratios)
        splits[split].append({"case_id": case.get("case_id"), "cluster": cluster})
    return splits


def resource_baseline(cases: list[Path]) -> dict:
    """对每个案例计时 audit_exp (EXP 语义) 与 analyze_heap_source (识别)。"""
    sys_path_setup()
    from pwncraft.features.audit.audit import audit_exp
    from pwncraft.features.heapviz import analyze_heap_source

    timings = {"audit_ms": [], "analyze_ms": [], "cases": []}
    for case in cases:
        exp_path = next((case / "original" / "solution").glob("*.py"), None)
        if exp_path is None:
            continue
        source = exp_path.read_text(encoding="utf-8")
        t0 = time.monotonic()
        diagnostics = audit_exp(source)
        audit_ms = (time.monotonic() - t0) * 1000
        t0 = time.monotonic()
        analyze_heap_source(source)
        analyze_ms = (time.monotonic() - t0) * 1000
        timings["audit_ms"].append(audit_ms)
        timings["analyze_ms"].append(analyze_ms)
        timings["cases"].append({
            "case_id": case.name,
            "audit_ms": round(audit_ms, 1),
            "analyze_ms": round(analyze_ms, 1),
            "diagnostics": len(diagnostics),
        })
    for key in ("audit_ms", "analyze_ms"):
        values = sorted(timings[key])
        if values:
            timings[f"{key}_p50"] = round(values[len(values) // 2], 1)
            timings[f"{key}_p95"] = round(values[int(len(values) * 0.95)], 1)
    return timings


def sys_path_setup() -> None:
    project = Path(__file__).resolve().parents[1] / "pwncraft"
    if str(project) not in sys.path:
        sys.path.insert(0, str(project))


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="resource_baseline")
    ap.add_argument("--corpus", default=str(Path(__file__).resolve().parents[1]
                                            / "heap-corpus" / "corpus"))
    args = ap.parse_args()
    corpus = Path(args.corpus)
    sys_path_setup()
    cases = [d for d in sorted(corpus.iterdir()) if d.is_dir()]
    timings = resource_baseline(cases)
    out = Path(__file__).resolve().parents[2] / "autocorrect" / "resource_baseline.json"
    out.write_text(json.dumps(timings, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"baseline: cases={len(timings['cases'])} "
          f"audit_p50={timings.get('audit_ms_p50')}ms "
          f"audit_p95={timings.get('audit_ms_p95')}ms "
          f"analyze_p50={timings.get('analyze_ms_p50')}ms "
          f"analyze_p95={timings.get('analyze_ms_p95')}ms -> {out}")


if __name__ == "__main__":
    main()
