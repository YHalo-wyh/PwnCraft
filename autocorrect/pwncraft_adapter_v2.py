#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cycle-6 authoritative adapter.

This adapter keeps the INFRA single-analysis invariant while making reviewed
TargetBehavior 1:N actions authoritative for allocator replay:

    source -> one HeapSession analysis -> CanonicalIR
           -> reviewed TargetBehavior
           -> expanded allocator replay -> collapsed parent snapshots
           -> all formal artifacts

The initial identity replay performed inside ``HeapSession.load`` is provisional
and discarded when reviewed allocator actions exist.  Source analysis is never
run twice.  Unbound cases retain the original adapter behavior.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import allocator_replay_v2
import pwncraft_adapter as base
import target_behavior_v2

HERE = Path(__file__).resolve().parent


def _target_behavior_for_case(
    case_id: str,
    canonical_ops: list[dict[str, Any]],
    canonical_objects: tuple[object, ...] | list[object],
) -> tuple[dict[str, Any], bool]:
    ac_case = HERE / "cases" / case_id
    bindings_path = ac_case / "behavior_bindings.json"
    if bindings_path.exists():
        bindings = target_behavior_v2.load_bindings(bindings_path)
        return target_behavior_v2.derive_target_behavior(canonical_ops, bindings), True
    return dict(base._target_actions_view(canonical_objects)), False


def run_case(case_dir: Path, out_path: Path | None = None) -> dict:
    from pwncraft.features.heapviz.bridge_session import HeapSession
    from pwncraft.features.heapviz.canvas_model import (
        build_canvas_semantic_model,
        check_canvas_invariants,
    )

    case_dir = Path(case_dir)
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    case_id = str(manifest["case_id"])
    exp_rel = manifest["exp_analysis"]["entry_file"]
    exp_path = case_dir / "original" / "solution" / Path(exp_rel).name
    if not exp_path.exists():
        candidates = list((case_dir / "original" / "solution").glob("*.py"))
        if not candidates:
            raise FileNotFoundError(f"no EXP under {case_dir}/original/solution")
        exp_path = candidates[0]
    exp_source = exp_path.read_text(encoding="utf-8")
    glibc = manifest.get("glibc", {}).get("version")

    # ONE source analysis. HeapSession.load performs a provisional identity
    # replay too; reviewed cases replace that replay below without re-analysis.
    session = HeapSession()
    allocator = {"version": glibc} if glibc else None
    state = session.load(source=exp_source, allocator=allocator)
    analysis = session.analysis
    if analysis is None:
        raise RuntimeError("HeapSession.load returned no analysis")

    canonical_ops = [base._canonical_view(op) for op in (analysis.canonical_operations or ())]
    target_behavior, reviewed_bindings = _target_behavior_for_case(
        case_id,
        canonical_ops,
        analysis.canonical_operations or (),
    )

    replay_plan = None
    if reviewed_bindings:
        state, replay_plan = allocator_replay_v2.replay_session(session, target_behavior)

    allocator_info = state.get("allocator") or {}
    recognition = (state.get("analysis") or {}).get("recognition") or {}

    # Keep the established truth-id lookup behavior; truth lock validation is
    # performed by the outer gate before this adapter is called.
    truth_id = ""
    for truth_name in ("expected_truth.json", "expected_analysis.json"):
        truth_path = case_dir / truth_name
        if not truth_path.exists():
            continue
        try:
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            truth_id = (truth.get("truth_lock") or {}).get("truth_id") or ""
            if truth_id:
                break
        except Exception:
            pass

    run_manifest = {
        "run_id": None,
        "case_id": case_id,
        "case_dir": str(case_dir),
        "exp_file": str(exp_path),
        "exp_sha256": base.sha256_text(exp_source),
        "binary_sha256": (manifest.get("target") or {}).get("binary_sha256"),
        "libc_sha256": (manifest.get("target") or {}).get("libc_sha256"),
        "glibc_version_claimed": glibc,
        "recognizer_revision": recognition.get("recognizer_revision"),
        "truth_id": truth_id,
        "comparator_version": "4.1",
        "allocator_profile_id": allocator_info.get("profile_id"),
        "allocator_profile_revision": allocator_info.get("profile_revision"),
        "allocator_requested_version": allocator_info.get("requested_version"),
        "allocator_mechanisms": allocator_info.get("mechanisms"),
        "memory_revision": state.get("memory_revision"),
        "snapshot_id": state.get("snapshot_id"),
        "analysis_valid": (state.get("analysis") or {}).get("valid"),
        "target_behavior_revision": target_behavior.get("revision") or "",
        "allocator_replay_revision": (
            replay_plan.revision if replay_plan is not None else "identity"
        ),
    }
    seed = "|".join(str(run_manifest[key]) for key in (
        "case_id", "exp_sha256", "recognizer_revision",
        "allocator_profile_id", "allocator_profile_revision",
        "memory_revision", "snapshot_id", "target_behavior_revision",
        "allocator_replay_revision",
    ))
    run_manifest["run_id"] = "run-" + hashlib.sha256(seed.encode()).hexdigest()[:16]

    contracts = [base._contract_view(contract) for contract in (analysis.helper_contracts or ())]
    steps = [step for step in (state.get("steps") or []) if isinstance(step, dict)]
    analyzer_view = {
        "run_id": run_manifest["run_id"],
        "valid": run_manifest["analysis_valid"],
        "recognizer_revision": run_manifest["recognizer_revision"],
        "recognition": {key: recognition.get(key) for key in
                        ("candidate_calls", "recognized", "ambiguous", "unknown",
                         "ignored", "truncated")},
        "diagnostics": [
            str(item) for item in ((state.get("analysis") or {}).get("diagnostics") or [])
        ][:40],
        "helper_contracts": contracts,
        "canonical_ops": canonical_ops,
    }

    target_behavior = dict(target_behavior)
    target_behavior["run_id"] = run_manifest["run_id"]
    replay_view = base._replay_view(steps)
    replay_view["run_id"] = run_manifest["run_id"]
    bridge_steps = {
        "run_id": run_manifest["run_id"],
        "snapshot_id": run_manifest["snapshot_id"],
        "memory_revision": run_manifest["memory_revision"],
        "steps": steps,
    }

    physical = []
    canvas_steps = []
    canvas_invariants = []
    for step, raw_snapshot in zip(steps, session.snapshots or []):
        physical_view = base._physical_view(
            step,
            raw_snapshot,
            memory_revision=state.get("memory_revision") or "",
        )
        physical_view["run_id"] = run_manifest["run_id"]
        physical.append(physical_view)
        canvas_model = build_canvas_semantic_model(step)
        canvas_model["run_id"] = run_manifest["run_id"]
        canvas_steps.append(canvas_model)
        canvas_invariants.append({
            "step": canvas_model["step"],
            "op_id": canvas_model["snapshot_id"],
            "violations": check_canvas_invariants(canvas_model, step),
        })

    allocator_plan_view = (
        replay_plan.to_dict() if replay_plan is not None
        else {
            "revision": "identity",
            "expanded_operation_count": len(session.scenario.operations),
            "parent_operation_count": len(session.scenario.operations),
            "expanded_parent_count": 0,
            "groups": [],
        }
    )
    allocator_plan_view["run_id"] = run_manifest["run_id"]

    out = {
        "run_id": run_manifest["run_id"],
        "case_id": case_id,
        "run_manifest": run_manifest,
        "analyzer": analyzer_view,
        "target_behavior": target_behavior,
        "allocator_replay_plan": allocator_plan_view,
        "replay": replay_view,
        "physical_memory": {"run_id": run_manifest["run_id"], "steps": physical},
        "bridge_steps": bridge_steps,
        "canvas_truth_model": {
            "definition": "CanvasTruthModel: what the backend truth says SHOULD be "
                          "presented. NOT a claim about the actual JS renderer plan "
                          "(INFRA-CLOSURE-1 P0-5).",
            "run_id": run_manifest["run_id"],
            "n_steps": len(canvas_steps),
            "steps": canvas_steps,
        },
        "canvas_invariants": canvas_invariants,
    }
    if out_path:
        base._write_artifacts(out, Path(out_path))
        artifact_dir = Path(out_path).parent
        (artifact_dir / "allocator_replay_plan.json").write_text(
            json.dumps(allocator_plan_view, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    return out
