#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EVIDENCE-SCOPE-CLOSURE acceptance tests.

T5  create(size) with EXP-side evidence only PASSES the HELPER_CONTRACT layer
    even when expected_truth carries a binary/source evidence tier — binary
    evidence is optional corroborating, never required (ownership rule).
T6  create's internal malloc×2 surfaces at TARGET_BEHAVIOR in the full-layer
    diagnostic while HELPER_CONTRACT stays MATCH (not swallowed upstream).
T7  a no-source case (helper tier=interaction_dataflow) is never failed for
    missing SOURCE evidence.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pwn宝"))

import comparator_v4 as C  # noqa: E402
import pwncraft_adapter as A  # noqa: E402

EXP_SOURCE = '''
def create(size, content):
    io.recvuntil("Choice:")
    io.sendline("1")
    io.recvuntil("Size:")
    io.sendline(str(size))
    io.recvuntil("Data:")
    io.sendline(content)

def delete(idx):
    io.recvuntil("Choice:")
    io.sendline("4")
    io.recvuntil("Idx:")
    io.sendline(str(idx))

def exp():
    create(0x18, "dada")
    delete(0)
'''


def _actual_from_recognizer():
    a = A.run_analyzer(EXP_SOURCE)
    return {
        "run_manifest": {"run_id": "run-scope-test01"},
        "analyzer": dict(a, run_id="run-scope-test01"),
        "target_behavior": {"run_id": "run-scope-test01", "derivation": "identity",
                            "per_op": []},
        "replay": {"run_id": "run-scope-test01", "n_steps": 0, "steps": []},
        "physical_memory": {"run_id": "run-scope-test01", "steps": []},
        "canvas_truth_model": {"run_id": "run-scope-test01", "steps": []},
        "canvas_invariants": [],
    }


def _helper_truth(tier):
    return {
        "case_id": "synthetic-scope",
        "helpers": [{
            "function": "create",
            "semantic": "alloc",
            "evidence_tier": tier,
            "roles": {"arg0": "size", "arg1": "data"},
            "confidence": 0.97,
            "evidence": ["prompt→send dataflow (EXP-side only in this test)"],
        }],
        "expected_operations": [],
        "allocator_events": {"per_call": []},
        "machine_checks": [],
    }


def test_t5_binary_tier_not_required_for_helper_contract():
    truth = _helper_truth("binary_source_dataflow")
    report = C.compare(truth, _actual_from_recognizer(), exp_source=EXP_SOURCE)
    helper = report["layer_results"][0]
    assert report["verdict"] == "MATCH", report.get("first_divergence")
    assert helper["status"] == "MATCH"
    assert helper["semantic_status"] == "MATCH"
    # the binary tier is recorded as optional-corroborating absence, not failure
    assert not helper["missing_required"]
    assert any("BINARY/SOURCE" in o for o in helper["optional_missing"])


def test_t7_interaction_tier_no_source_case_passes():
    truth = _helper_truth("interaction_dataflow")
    report = C.compare(truth, _actual_from_recognizer(), exp_source=EXP_SOURCE)
    helper = report["layer_results"][0]
    assert report["verdict"] == "MATCH"
    assert helper["status"] == "MATCH"
    assert not helper["missing_required"]


def test_t6_1n_not_swallowed_by_helper_layer():
    truth = {
        "case_id": "synthetic-scope-1n",
        "helpers": [_helper_truth("binary_source_dataflow")["helpers"][0]],
        "expected_operations": [],
        "allocator_events": {"per_call": [{
            "source_line": 17,
            "call": "create(0x18, 'dada')",
            "events": [{"kind": "malloc", "request": "0x10"},
                       {"kind": "malloc", "request": "0x18"}],
        }]},
        "machine_checks": [],
    }
    actual = _actual_from_recognizer()
    # wire the recognized create call into target_behavior/IR so the layer runs
    analysis = A.run_analyzer(EXP_SOURCE)
    canon = analysis["canonical_ops"]
    create_ops = [o for o in canon if o.get("source_line") == 17 and
                  o.get("kind") == "alloc"]
    assert create_ops, "create call not recognized in synthetic EXP"
    actual["target_behavior"]["per_op"] = [{
        "op_id": create_ops[0]["op_id"], "kind": "alloc", "source_line": 17,
        "actions": [{"action": "malloc", "request": create_ops[0]["allocator_request"]}],
        "internals_not_modeled": True,
    }]
    report = C.diagnose_layers(truth, actual, exp_source=EXP_SOURCE)
    by_layer = {r["layer"]: r for r in report["layer_results"]}
    assert by_layer["HELPER_CONTRACT"]["status"] == "MATCH", by_layer["HELPER_CONTRACT"]
    assert by_layer["TARGET_BEHAVIOR"]["status"] == "DIVERGED"
    assert by_layer["TARGET_BEHAVIOR"]["missing_required"] == [
        "SOURCE_INTERNAL_ACTION_FLOW", "BINARY_INTERNAL_ACTION_FLOW"]
    # first divergence (early-stop) lands at TARGET_BEHAVIOR: helpers are clean
    assert report["first_divergence"]["layer"] == "TARGET_BEHAVIOR"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all evidence-scope tests passed")
