#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Artifact-aware accepted-truth regression gate.

This is the CI-safe closure for the accepted-case gate:
- deduplicate accepted case ids;
- require a valid locked truth;
- perform one fresh authoritative run per case;
- write sidecars into generated/truthregress/;
- compare with the case evaluation contract so deferred layers stay deferred;
- apply the real contract gate only after the fresh artifact directory exists.

The comparator currently invokes evaluation_contract.enforce() internally before
it can be told where the fresh sidecars live.  During the semantic comparison we
therefore replace only that final enforcement call with a pass-through, while
still passing the contract into comparator_v4 so layer applicability is honored.
The original deterministic enforcement function is restored immediately and is
then applied to the report with _case_dir pinned to the fresh artifact directory.
No truth or recognizer semantics are modified here.
"""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT / "pwncraft"
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import comparator_v4  # noqa: E402
import evaluation_contract  # noqa: E402
import pwncraft_adapter  # noqa: E402
import loop as loop_cli  # noqa: E402


def _accepted_case_ids() -> list[str]:
    registry_path = HERE / "accepted_cases.json"
    if not registry_path.exists():
        return []
    loaded = json.loads(registry_path.read_text(encoding="utf-8"))
    if isinstance(loaded, list):
        raw = loaded
    else:
        raw = (loaded or {}).get("case_acceptances") or []
    ids: list[str] = []
    seen: set[str] = set()
    for item in raw:
        case_id = str(item.get("case_id") if isinstance(item, dict) else item or "").strip()
        if case_id and case_id not in seen:
            seen.add(case_id)
            ids.append(case_id)
    return ids


def _compare_after_fresh_artifacts(expected: dict, actual: dict, exp_source: str,
                                   contract, artifact_dir: Path) -> dict:
    """Compare with contract applicability, then enforce artifact completeness."""
    real_enforce = evaluation_contract.enforce
    try:
        evaluation_contract.enforce = lambda report, _contract: report
        report = comparator_v4.compare(
            expected,
            actual,
            exp_source=exp_source,
            contract=contract,
        )
    finally:
        evaluation_contract.enforce = real_enforce

    report["_case_dir"] = str(artifact_dir)
    return real_enforce(report, contract)


def run_gate() -> int:
    case_ids = _accepted_case_ids()
    out_path = HERE / "regression" / "truth_regression.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not case_ids:
        payload = {"results": [], "note": "empty accepted case registry"}
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print("[truthregress-ci] accepted case registry empty -> exit 0")
        return 0

    results: list[dict] = []
    failed = False
    for case_id in case_ids:
        cdir = HERE / "cases" / case_id
        try:
            truth_path = loop_cli._truth_path(cdir)
            if not truth_path.exists():
                raise RuntimeError("expected truth missing")
            loop_cli._check_truth_lock(cdir, strict=True)

            case_dir = loop_cli.resolve_case(case_id)
            exp_candidates = list((case_dir / "original" / "solution").glob("*.py"))
            if not exp_candidates:
                raise RuntimeError("EXP source missing")
            exp_source = exp_candidates[0].read_text(encoding="utf-8")
            expected = json.loads(truth_path.read_text(encoding="utf-8"))

            gen_dir = cdir / "generated" / "truthregress"
            actual = pwncraft_adapter.run_case(
                case_dir,
                out_path=gen_dir / "pwncraft_output.json",
            )
            contract = evaluation_contract.load_contract(cdir)
            report = _compare_after_fresh_artifacts(
                expected,
                actual,
                exp_source,
                contract,
                gen_dir,
            )
            fd = report.get("first_divergence") or {}
            verdict = str(report.get("verdict") or "INCONCLUSIVE")
            row = {
                "case_id": case_id,
                "verdict": verdict,
                "layer": fd.get("layer"),
                "assertions": report.get("assertion_counts"),
                "run_id": (actual.get("run_manifest") or {}).get("run_id"),
                "artifact_dir": str(gen_dir),
            }
            results.append(row)
            print(
                f"[truthregress-ci] {case_id}: {verdict}"
                + (f" @ {fd.get('layer')}" if fd.get("layer") else "")
            )
            if verdict != "MATCH":
                failed = True
        except BaseException as exc:  # formal gate must preserve a machine-readable failure
            failed = True
            results.append({
                "case_id": case_id,
                "verdict": "BLOCKED",
                "reason": f"{type(exc).__name__}: {exc}",
            })
            print(f"[truthregress-ci] {case_id}: BLOCKED ({type(exc).__name__}: {exc})")
            traceback.print_exc()

    payload = {
        "gate": "artifact-aware accepted truth regression",
        "results": results,
        "failed": failed,
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[truthregress-ci] failed={failed} -> exit {'1' if failed else '0'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run_gate())
