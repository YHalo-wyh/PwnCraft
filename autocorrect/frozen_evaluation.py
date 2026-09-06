#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M5 封存评测执行 (frozen_test split)。

对 splits.json 的 frozen_test 案例逐个执行独立评测（有真值则 comparator，
无真值则 INCONCLUSIVE 如实写入）。结果写入 frozen_evaluation.json。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AC = ROOT / "autocorrect"
CORPUS = ROOT / "heap-corpus" / "corpus"


def main() -> None:
    sys.path.insert(0, str(AC))
    sys.path.insert(0, str(ROOT / "pwn宝"))
    import comparator_v4
    import evaluation_contract
    import pwncraft_adapter

    splits_path = AC / "splits.json"
    if not splits_path.exists():
        print("[frozen] splits.json not found")
        return
    splits = json.loads(splits_path.read_text(encoding="utf-8"))
    frozen = splits.get("frozen_test", [])
    if not frozen:
        print("[frozen] frozen_test split 为空")
        return

    results = []
    for entry in frozen:
        case_id = entry["case_id"]
        case_dir = CORPUS / case_id
        cdir = AC / "cases" / case_id
        truth_path = cdir / "expected_truth.json"
        if not truth_path.exists():
            # 无真值 → INCONCLUSIVE 如实写入 (owner: 不做虚假通过)
            results.append({
                "case_id": case_id,
                "verdict": "INCONCLUSIVE",
                "reason": "frozen_test 案例无独立金标准真值 (expected_truth.json "
                          "尚未建立); 封存集样本数不足以支持统计结论",
                "truth_id": None,
            })
            print(f"[frozen] {case_id[:50]}: INCONCLUSIVE (no truth)")
            continue
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        lock = truth.get("truth_lock") or {}
        exp_path = next((case_dir / "original" / "solution").glob("*.py"), None)
        if exp_path is None:
            results.append({"case_id": case_id, "verdict": "INCONCLUSIVE",
                            "reason": "no EXP"})
            continue
        result = pwncraft_adapter.run_case(case_dir)
        report = comparator_v4.compare(
            truth, result,
            exp_source=exp_path.read_text(encoding="utf-8"))
        fd = report.get("first_divergence") or {}
        results.append({
            "case_id": case_id,
            "verdict": report["verdict"],
            "layer": fd.get("layer"),
            "truth_id": lock.get("truth_id"),
            "run_id": (result.get("run_manifest") or {}).get("run_id"),
        })
        print(f"[frozen] {case_id[:50]}: {report['verdict']}"
              + (f" @ {fd.get('layer')}" if fd.get("layer") else ""))

    out = AC / "regression" / "frozen_evaluation.json"
    out.write_text(json.dumps({
        "milestone": "M5 封存评测 (阶段 0.1+0.3)",
        "frozen_count": len(frozen),
        "results": results,
        "note": "封存集样本数不足以支持统计结论; 逐案例结果如实记录",
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    inconclusive = sum(1 for r in results if r["verdict"] == "INCONCLUSIVE")
    print(f"[frozen] total={len(results)} inconclusive={inconclusive} -> {out}")


if __name__ == "__main__":
    main()
