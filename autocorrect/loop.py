#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PwnCraft AI auto-correction loop CLI.

Workflow (reviewer_protocol.md):
  run      : corpus case -> PwnCraft static recognition + replay (pwncraft_output.json)
  compare  : expected_analysis.json vs pwncraft_output.json -> first divergence report
  baseline : record current behavior fingerprint of a case
  regress  : re-run all baselined cases, flag any drift (must be STABLE or
             explicitly refreshed together with an accepted fix)

Static analysis only; challenge binaries are never executed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pwncraft_adapter  # noqa: E402
import comparator  # noqa: E402
import comparator_v3  # noqa: E402  (kept for audit trail)
import comparator_v4  # noqa: E402
import regression  # noqa: E402

CORPUS = HERE.parent / "heap-corpus" / "corpus"


def resolve_case(case: str) -> Path:
    p = Path(case)
    if p.is_dir():
        return p
    guess = CORPUS / case
    if guess.is_dir():
        return guess
    matches = list(CORPUS.glob(f"{case}*"))
    if len(matches) == 1:
        return matches[0]
    raise FileNotFoundError(f"case dir not found for: {case}")


def cmd_generate(args):
    """Phase B: ONE authoritative run -> atomic artifact directory (P0-2/P1-4).

    Truth lock is verified before any run (P1-2)."""
    case_dir = resolve_case(args.case)
    cid = case_dir.name
    cdir = HERE / "cases" / cid
    _check_truth_lock(cdir, strict=False)
    gen_dir = cdir / "generated" / (args.label or "baseline")
    result = pwncraft_adapter.run_case(case_dir, out_path=gen_dir / "pwncraft_output.json")
    a = result["analyzer"]
    rm = result["run_manifest"]
    print(f"[generate] {cid} label={args.label or 'baseline'} -> {gen_dir}")
    print(f"           run_id={rm['run_id']} ops={len(a['canonical_ops'])} "
          f"contracts={len(a['helper_contracts'])} steps={result['replay']['n_steps']} "
          f"revision={rm['recognizer_revision']} profile={rm['allocator_profile_id']}")


def cmd_diverge(args):
    """Reviewer: compare locked expected_truth vs generated output.
    v3 comparator (protocol v1.1): six-field helper comparison,
    SEMANTIC_MATCH/EVIDENCE_DIVERGED provenance check, 1:N allocator events."""
    case_dir = resolve_case(args.case)
    cid = case_dir.name
    cdir = HERE / "cases" / cid
    expected = json.loads((cdir / "expected_truth.json").read_text(encoding="utf-8"))
    gen_name = args.label or "baseline"
    actual_path = cdir / "generated" / gen_name / "pwncraft_output.json"
    actual = json.loads(actual_path.read_text(encoding="utf-8"))
    exp_rel = expected.get("exp_file") or ""
    exp_path = case_dir / "original" / "solution" / "exp.py"
    if not exp_path.exists():
        cands = list((case_dir / "original" / "solution").glob("*.py"))
        exp_path = cands[0] if cands else None
    exp_source = exp_path.read_text(encoding="utf-8") if exp_path else ""
    plan_path = cdir / "generated" / gen_name / "renderer_plan.json"
    renderer_plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else None
    report = comparator_v4.compare(expected, actual, exp_source=exp_source,
                                   renderer_plan=renderer_plan)
    report["compared_artifacts"] = {
        "expected_truth": str(cdir / "expected_truth.json"),
        "pwncraft_output": str(actual_path),
        "renderer_plan": str(plan_path) if renderer_plan else None,
        "run_id": (actual.get("run_manifest") or {}).get("run_id"),
        "comparator": "v4",
    }
    out = cdir / f"divergence_report.{gen_name}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[diverge] verdict={report['verdict']} -> {out}")
    fd = report.get("first_divergence")
    if fd:
        print(f"          first_divergence layer={fd['layer']} "
              f"line={fd.get('source_line')} call={fd.get('source_call')}")
        sd = fd.get("status_detail") or {}
        print(f"          status: {sd.get('semantic')} / {sd.get('evidence', sd.get('layer_detail', ''))}"
              + (f" field={sd.get('divergence_field')}" if sd.get('divergence_field') else ""))
        print(f"          hint: {report.get('reviewer_reason_hint', '')[:220]}")
    for h in report.get("helper_contract_status", []):
        print(f"          helper {h.get('helper'):10} {h.get('semantic')}"
              + (f" / {h.get('evidence')}" if h.get("evidence") else ""))


def cmd_run(args):
    case_dir = resolve_case(args.case)
    result = pwncraft_adapter.run_case(case_dir)  # in-memory only; artifacts via generate
    print(f"[run] {result['case_id']} run_id={result['run_id']}")
    print(f"      ops={len(result['analyzer']['canonical_ops'])} "
          f"contracts={len(result['analyzer']['helper_contracts'])} "
          f"steps={result['replay']['n_steps']} "
          f"revision={result['run_manifest']['recognizer_revision']}")


def cmd_compare(args):
    case_dir = resolve_case(args.case)
    cdir = HERE / "cases" / case_dir.name
    expected_path = cdir / "expected_analysis.json"
    actual_path = cdir / "pwncraft_output.json"
    if not actual_path.exists():
        cmd_run(argparse.Namespace(case=str(case_dir)))
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    actual = json.loads(actual_path.read_text(encoding="utf-8"))
    expected["_path"] = str(expected_path)
    actual["_path"] = str(actual_path)
    report = comparator.compare(expected, actual)
    report["compared_artifacts"]["expected_analysis"] = str(expected_path)
    report["compared_artifacts"]["pwncraft_output"] = str(actual_path)
    out_path = cdir / "divergence_report.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[compare] verdict={report['verdict']} -> {out_path}")
    fd = report.get("first_divergence")
    if fd:
        print(f"          first_divergence layer={fd['layer']} loc={fd.get('location')}")
        print(f"          root_cause: {report.get('root_cause')}")


def _case_ids():
    ids = []
    for p in sorted((HERE / "regression" / "baselines").glob("*.json")):
        ids.append(p.stem)
    return ids


def cmd_baseline(args):
    case_dir = resolve_case(args.case)
    result = pwncraft_adapter.run_case(case_dir)  # single authoritative run, no sidecar write
    rec = regression.save_version(
        result, HERE / "regression" / "baselines",
        label=args.label, patch_id=args.patch_id, note=args.note or "",
        intentional_delta=[x for x in (args.intentional_delta or "").split(",") if x])
    print(f"[baseline] {result['case_id']} {args.label}__{args.patch_id} digest={rec['digest']}")


def cmd_explain(args):
    baselines_root = HERE / "regression" / "baselines"
    rec = regression.add_explanation(
        baselines_root, args.case, args.from_version, args.patch_id,
        [x for x in args.dimensions.split(",") if x], args.note or "")
    print(f"[explain] {args.case}: patch {args.patch_id} explains "
          f"{rec['dimensions']} vs {args.from_version}")


def cmd_regress(args):
    results = []
    baselines_root = HERE / "regression" / "baselines"
    case_ids = sorted(p.name for p in baselines_root.iterdir() if p.is_dir()) \
        if baselines_root.exists() else []
    for case_id in case_ids:
        case_dir = resolve_case(case_id)
        result = pwncraft_adapter.run_case(case_dir)
        results.append(regression.check_all_versions(result, baselines_root))
    (HERE / "regression" / "last_run.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    bad = [r for r in results if r["status"] == "REGRESSION"]
    for r in results:
        print(f"[regress] {r['case_id']}: {r['status']}")
        for v in r.get("versions", []):
            extra = f" drift={v['unexplained_drift']}" if v.get("unexplained_drift") else ""
            print(f"          vs {v['label']}__{v['patch_id']}: {v['status']}{extra}")
    print(f"[regress] total={len(results)} regressions={len(bad)}")
    sys.exit(1 if bad else 0)



def _truth_path(cdir):
    for name in ("expected_truth.json", "expected_analysis.json"):
        p = cdir / name
        if p.exists():
            return p
    return cdir / "expected_truth.json"


def _check_truth_lock(cdir, strict=True):
    import hashlib
    p = _truth_path(cdir)
    if not p.exists():
        return
    data = json.loads(p.read_text(encoding="utf-8"))
    lock = data.get("truth_lock")
    if not lock:
        msg = f"truth not locked: {p} (run: python loop.py lock-truth <case>)"
        if strict:
            raise SystemExit(f"[lock] {msg}")
        print(f"[lock] WARNING {msg}")
        return
    payload = {k: v for k, v in data.items() if k != "truth_lock"}
    digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False,
                                       sort_keys=True).encode("utf-8")).hexdigest()
    if lock.get("content_sha256") != digest:
        raise SystemExit(f"[lock] content hash mismatch for {p}: truth edited in place "
                         "-- forbidden (P1-2). Create a new revision instead.")


def cmd_lock_truth(args):
    import hashlib
    import datetime
    case_dir = resolve_case(args.case)
    p = _truth_path(HERE / "cases" / case_dir.name)
    if not p.exists():
        raise SystemExit(f"[lock] no truth file for {case_dir.name}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("truth_lock"):
        print(f"[lock] already locked: {p}")
        return
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    payload = dict(data)
    digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False,
                                       sort_keys=True).encode("utf-8")).hexdigest()
    exp_file = next((case_dir / "original" / "solution").glob("*.py"))
    data["truth_lock"] = {
        "truth_id": "truth-" + digest[:16],
        "content_sha256": digest,
        "schema_version": "1.2-layered" if "truth_layers" in data else "1.0-flat",
        "locked_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "analyst_input_hashes": {
            "binary_sha256": (manifest.get("target") or {}).get("binary_sha256"),
            "libc_sha256": (manifest.get("target") or {}).get("libc_sha256"),
            "exp_sha256": hashlib.sha256(exp_file.read_bytes()).hexdigest(),
        },
        "truth_revision": 1,
        "superseded_by": None,
    }
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[lock] locked {p} truth_id={data['truth_lock']['truth_id']}")



def cmd_supersede_truth(args):
    """P1-2: truth falsified by new evidence -> NEW revision. The locked file
    is never edited in place: current truth becomes a superseded revision
    (with revision_reason), the analyst-prepared file installs as revision N+1
    with a fresh lock."""
    import hashlib
    import datetime
    case_dir = resolve_case(args.case)
    cdir = HERE / "cases" / case_dir.name
    old_path = _truth_path(cdir)
    if not old_path.exists():
        raise SystemExit(f"[supersede] no truth file for {case_dir.name}")
    old = json.loads(old_path.read_text(encoding="utf-8"))
    lock = old.get("truth_lock")
    if not lock:
        raise SystemExit("[supersede] current truth is not locked; lock it first")
    _check_truth_lock(cdir, strict=True)
    new_file = Path(args.new)
    if not new_file.exists():
        raise SystemExit(f"[supersede] new truth file not found: {new_file}")
    new_data = json.loads(new_file.read_text(encoding="utf-8"))
    if "truth_lock" in new_data:
        raise SystemExit("[supersede] new truth must be UNLOCKED (lock happens here)")
    rev = int(lock.get("truth_revision") or 1)
    superseded_name = f"{old_path.stem}.rev{rev}.superseded.json"
    old["truth_lock"] = dict(lock)
    old["truth_lock"]["superseded_by"] = None
    old["supersede_record"] = {
        "revision_reason": args.reason or "",
        "superseded_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "successor": old_path.name,
    }
    (cdir / superseded_name).write_text(
        json.dumps(old, ensure_ascii=False, indent=2), encoding="utf-8")
    payload = dict(new_data)
    digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False,
                                       sort_keys=True).encode("utf-8")).hexdigest()
    new_data["truth_lock"] = {
        "truth_id": "truth-" + digest[:16],
        "content_sha256": digest,
        "schema_version": lock.get("schema_version", "1.0-flat"),
        "locked_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "analyst_input_hashes": lock.get("analyst_input_hashes", {}),
        "truth_revision": rev + 1,
        "supersedes": {"file": superseded_name, "truth_id": lock.get("truth_id"),
                       "revision_reason": args.reason or ""},
    }
    old_path.write_text(json.dumps(new_data, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"[supersede] rev{rev} -> {superseded_name}; installed rev{rev + 1} "
          f"truth_id={new_data['truth_lock']['truth_id']}")


def cmd_truthregress(args):
    """P1-1 Truth Regression: fresh authoritative run + strict comparator for
    every ACCEPTED case (registry). ACCEPTED case turning DIVERGED = reject."""
    registry = HERE / "accepted_cases.json"
    accepted = json.loads(registry.read_text(encoding="utf-8")) if registry.exists() else []
    if not accepted:
        accepted = sorted(q.name for q in (HERE / "cases").iterdir()
                          if (q / "expected_truth.json").exists())
        print("[truthregress] registry empty -- running over locked-truth cases "
              "(none ACCEPTED yet; proves executability)")
    results = []
    for case_id in accepted:
        case_dir = resolve_case(case_id)
        cdir = HERE / "cases" / case_dir.name
        if not (cdir / "expected_truth.json").exists():
            continue
        _check_truth_lock(cdir, strict=False)
        expected = json.loads((cdir / "expected_truth.json").read_text(encoding="utf-8"))
        exp_path = next((case_dir / "original" / "solution").glob("*.py"))
        result = pwncraft_adapter.run_case(case_dir)
        report = comparator_v4.compare(expected, result,
                                       exp_source=exp_path.read_text(encoding="utf-8"))
        fd = report.get("first_divergence") or {}
        results.append({"case_id": case_id, "verdict": report["verdict"],
                        "layer": fd.get("layer"),
                        "run_id": (result.get("run_manifest") or {}).get("run_id")})
        print(f"[truthregress] {case_id}: {report['verdict']}"
              + (f" @ {fd.get('layer')}" if fd.get("layer") else ""))
    (HERE / "regression" / "truth_regression.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[truthregress] {len(results)} cases -> regression/truth_regression.json")


def main():
    ap = argparse.ArgumentParser(prog="autocorrect")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "compare"):
        p = sub.add_parser(name)
        p.add_argument("case", help="case_id or corpus dir")
    b = sub.add_parser("baseline")
    b.add_argument("case", help="case_id or corpus dir")
    b.add_argument("--label", required=True, help="version label (pre-patch/post-patch/...)")
    b.add_argument("--patch-id", default="", help="patch id this baseline belongs to")
    b.add_argument("--note", default="")
    b.add_argument("--intentional-delta", default="",
                   help="comma-separated fingerprint dimensions explained by patch_id")
    lt = sub.add_parser("lock-truth")
    lt.add_argument("case", help="case_id or corpus dir")
    st = sub.add_parser("supersede-truth")
    st.add_argument("case", help="case_id or corpus dir")
    st.add_argument("--new", required=True, help="path to UNLOCKED revised truth json")
    st.add_argument("--reason", required=True, help="revision_reason")
    tr = sub.add_parser("truthregress")
    e = sub.add_parser("explain")
    e.add_argument("case", help="case_id")
    e.add_argument("--from-version", required=True, help="baseline version file (e.g. pre-patch__none.json)")
    e.add_argument("--patch-id", required=True)
    e.add_argument("--dimensions", required=True, help="comma-separated drift dimensions")
    e.add_argument("--note", default="")
    r = sub.add_parser("regress")
    g = sub.add_parser("generate")
    g.add_argument("case", help="case_id or corpus dir")
    g.add_argument("--label", default="baseline",
                   help="artifact subdirectory label (baseline / after / ...)")
    d = sub.add_parser("diverge")
    d.add_argument("case", help="case_id or corpus dir")
    d.add_argument("--label", default="baseline",
                   help="which generated/ run to compare against")
    args = ap.parse_args()
    {"run": cmd_run, "compare": cmd_compare, "generate": cmd_generate,
     "diverge": cmd_diverge, "baseline": cmd_baseline, "regress": cmd_regress,
     "explain": cmd_explain, "lock-truth": cmd_lock_truth,
     "truthregress": cmd_truthregress,
     "supersede-truth": cmd_supersede_truth}[args.cmd](args)


if __name__ == "__main__":
    main()
