#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Versioned regression baselines (protocol v1.1 §E).

Full version history per case; nothing is destructively overwritten:
    regression/baselines/<case_id>/index.json
    regression/baselines/<case_id>/<label>__<patch_id>.json

Each version records: patch_id, label (pre-patch|post-patch|...), digest,
fingerprint, note, intentional_delta (the drift dimensions EXPLAINED and
ACCEPTED together with patch_id). accepted_truth is NOT stored here and is
never auto-refreshed by patches.

Regression check compares the current behavior fingerprint against EVERY
stored version and reports per-version alignment.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


# ---------------------------------------------------------------- fingerprint

def fingerprint(pwncraft_output: dict) -> dict:
    a = pwncraft_output.get("analyzer") or {}
    r = pwncraft_output.get("replay") or {}
    contracts = []
    for c in a.get("helper_contracts", []):
        roles = c.get("roles") if isinstance(c.get("roles"), dict) else {}
        contracts.append({
            "function": c.get("function"),
            "operation": c.get("operation"),
            "candidate_operation": c.get("candidate_operation"),
            "confidence": c.get("confidence"),
            "evidence_sources": sorted(c.get("evidence_sources") or []),
            "roles": sorted(roles.keys()),
            "role_params": sorted(
                (rr.get("parameter"), k) for k, rr in roles.items()
                if isinstance(rr, dict)),
        })
    ops = [
        [o.get("source_line"), o.get("kind"), _concrete_key(o.get("handle")),
         _concrete_key(o.get("allocator_request"))]
        for o in a.get("canonical_ops", [])
    ]
    steps = [
        [s.get("step"), s.get("n_chunks"), s.get("aborted"),
         _bins_key(s.get("fastbins")), _bins_key(s.get("tcache")),
         _bins_key(s.get("unsorted")),
         [(e.get("kind"), e.get("request_size") or e.get("destination_bin"))
          for e in (s.get("alloc_events") or []) + (s.get("free_events") or [])]]
        for s in r.get("steps", [])
    ]
    return json.loads(json.dumps({
        "recognizer_revision": a.get("recognizer_revision"),
        "n_ops": len(a.get("canonical_ops", [])),
        "helper_contracts": contracts,
        "op_sequence": ops,
        "replay_steps": steps,
        "replay_n_steps": r.get("n_steps"),
    }, ensure_ascii=False, default=str))


def _concrete_key(av):
    if isinstance(av, dict):
        if av.get("kind") == "concrete":
            for k, v in av.items():
                if k not in ("kind", "source"):
                    return v
            return None
        if av.get("kind") == "unknown":
            return f"?{av.get('reason', '')[:40]}"
        if av.get("kind") == "symbolic":
            return f"${av.get('expression', '')}"
    return str(av)[:40]


def _bins_key(v):
    if isinstance(v, dict):
        return sorted((k, tuple(x[:8] for x in lst)) for k, lst in v.items() if isinstance(lst, list))
    return v


def digest(fp: dict) -> str:
    blob = json.dumps(fp, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------- store

def _case_dir(baselines_root: Path, case_id: str) -> Path:
    d = Path(baselines_root) / case_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_version(pwncraft_output: dict, baselines_root: Path, label: str,
                 patch_id: str = "", note: str = "",
                 intentional_delta: list | None = None) -> dict:
    case_id = pwncraft_output.get("case_id")
    d = _case_dir(baselines_root, case_id)
    fp = fingerprint(pwncraft_output)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label or "unlabeled")
    safe_patch = re.sub(r"[^A-Za-z0-9_.-]+", "-", patch_id or "nopatch")
    fname = f"{safe_label}__{safe_patch}.json"
    path = d / fname
    if path.exists():
        raise FileExistsError(
            f"baseline version exists, never overwrite: {path} "
            "(append a new version or extend intentional_delta explicitly)")
    rec = {
        "case_id": case_id,
        "label": label,
        "patch_id": patch_id,
        "digest": digest(fp),
        "fingerprint": fp,
        "note": note,
        "intentional_delta": intentional_delta or [],
    }
    path.write_text(json.dumps(rec, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    index_path = d / "index.json"
    index = []
    if index_path.exists():
        index = json.loads(index_path.read_text(encoding="utf-8"))
    index = [i for i in index if i["file"] != fname]
    index.append({"file": fname, "label": label, "patch_id": patch_id,
                  "digest": rec["digest"], "note": note,
                  "intentional_delta": rec["intentional_delta"]})
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    return rec


def _explanations_path(baselines_root: Path, case_id: str) -> Path:
    return Path(baselines_root) / case_id / "explanations.json"


def add_explanation(baselines_root: Path, case_id: str, from_version_file: str,
                    patch_id: str, dimensions: list[str], note: str = "") -> dict:
    """Append-only: record that patch_id explains the drift of given
    fingerprint dimensions relative to an existing baseline version. History
    files are never modified (v1.1 §E)."""
    path = _explanations_path(baselines_root, case_id)
    records = []
    if path.exists():
        records = json.loads(path.read_text(encoding="utf-8"))
    rec = {"from_version_file": from_version_file, "patch_id": patch_id,
           "dimensions": dimensions, "note": note}
    # idempotent replace-by-key on append (same key => same content expected)
    key = (from_version_file, patch_id)
    for i, existing in enumerate(records):
        if (existing.get("from_version_file"), existing.get("patch_id")) == key:
            if existing != rec:
                raise ValueError(f"conflicting explanation for {key}: history is immutable")
            return rec
    records.append(rec)
    path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    return rec


def check_all_versions(pwncraft_output: dict, baselines_root: Path) -> dict:
    case_id = pwncraft_output.get("case_id")
    d = Path(baselines_root) / case_id
    index_path = d / "index.json"
    if not index_path.exists():
        return {"case_id": case_id, "status": "NO_BASELINE", "versions": []}
    explanations = []
    exp_path = _explanations_path(baselines_root, case_id)
    if exp_path.exists():
        explanations = json.loads(exp_path.read_text(encoding="utf-8"))
    fp_now = fingerprint(pwncraft_output)
    versions = []
    overall = "STABLE"
    for meta in json.loads(index_path.read_text(encoding="utf-8")):
        rec = json.loads((d / meta["file"]).read_text(encoding="utf-8"))
        base_fp = rec.get("fingerprint", {})
        drift = []
        for dim in ("recognizer_revision", "helper_contracts", "op_sequence", "replay_steps"):
            if base_fp.get(dim) != fp_now.get(dim):
                drift.append(dim)
        explained = set(rec.get("intentional_delta") or [])
        for ex in explanations:
            if ex.get("from_version_file") == meta["file"]:
                explained.update(ex.get("dimensions") or [])
        unexplained = [x for x in drift if x not in explained]
        vstatus = "MATCH" if not drift else ("EXPLAINED_DELTA" if not unexplained else "DRIFT")
        if vstatus == "DRIFT":
            overall = "REGRESSION"
        versions.append({
            "label": rec.get("label"), "patch_id": rec.get("patch_id"),
            "digest": rec.get("digest"), "status": vstatus,
            "drift": drift, "unexplained_drift": unexplained,
        })
    return {"case_id": case_id, "status": overall, "versions": versions}
