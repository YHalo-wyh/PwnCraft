#!/usr/bin/env python3
"""Offline, read-only audit for pinned public Chinese CTF Pwn source catalog.

It never downloads, executes or promotes an external file to ground truth.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
CATALOG = HERE / "public_china_pwn_corpus.json"
SPLITS = HERE / "splits.json"
VALID_SPLITS = ("train", "validation", "frozen_test")


def audit_catalog(catalog_path: Path = CATALOG, splits_path: Path = SPLITS,
                  cases_dir: Path | None = None) -> dict:
    data = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("cases"), list):
        raise ValueError("Unsupported catalog schema")
    splits = json.loads(Path(splits_path).read_text(encoding="utf-8"))
    split_index = {}
    for label in VALID_SPLITS:
        if not isinstance(splits.get(label), list):
            raise ValueError(f"Invalid split {label}")
        for row in splits[label]:
            key = row.get("case_id")
            if key in split_index:
                raise ValueError(f"Duplicate registered split: {key}")
            split_index[key] = label
    seen, competition_splits = set(), defaultdict(set)
    found, pending = [], []
    for item in data["cases"]:
        case_id = item.get("case_id", "")
        if not re.fullmatch(r"cn-[a-z0-9-]+", case_id):
            raise ValueError(f"Invalid case ID: {case_id!r}")
        if case_id in seen:
            raise ValueError(f"Duplicate case ID: {case_id}")
        seen.add(case_id)
        label = item.get("split")
        if label not in VALID_SPLITS or split_index.get(case_id) != label:
            raise ValueError(f"Split not registered or mismatched for {case_id}")
        competition_splits[item.get("competition", "")].add(label)
        repo = item.get("repository", "")
        rev = item.get("revision", "")
        material = item.get("material_path", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError(f"Invalid repository for {case_id}")
        if not re.fullmatch(r"[a-f0-9]{40}", rev):
            raise ValueError(f"Missing pinned commit for {case_id}")
        if not material or material.startswith("/") or ".." in Path(material).parts:
            raise ValueError(f"Invalid material path for {case_id}")
        if item.get("material_status") != "not_imported":
            raise ValueError("Source catalog must not claim unverified material readiness")
        case_root = (Path(cases_dir) if cases_dir else HERE / "cases") / case_id
        if (case_root / "manifest.json").is_file():
            found.append(case_id)
        else:
            pending.append(case_id)
    for competition, labels in competition_splits.items():
        if len(labels) != 1:
            raise ValueError(f"Cross-split competition leak: {competition}: {sorted(labels)}")
    return {
        "catalog_valid": True,
        "total": len(seen),
        "by_split": dict(Counter(item["split"] for item in data["cases"])),
        "by_competition": dict(Counter(item["competition"] for item in data["cases"])),
        "manifest_present_not_yet_verified": found,
        "pending_material_import": pending,
        "warning": "No candidate is training-ready until the existing challenge_intake.py "
                   "material and split gate accepts independently verified binary/EXP/source.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline China Pwn source catalog audit")
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--splits", type=Path, default=SPLITS)
    parser.add_argument("--cases-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_catalog(args.catalog, args.splits, args.cases_dir)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.exit(1, f"catalog validation failed: {exc}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
