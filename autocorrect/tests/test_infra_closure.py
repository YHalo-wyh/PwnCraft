#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""INFRA-CLOSURE-1 synthetic regressions.

T1  anti-positional alignment: value/init steps interleaved in the snapshot
    stream must not shift op↔snapshot alignment (P0-1).
T2  run_id gate: mixed-run artifacts are refused (P0-2).
T3  TARGET_BEHAVIOR vs ALLOCATOR are separate layers with separate failure
    modes (P0-3).
T4  OUTPUT_DATA_FLOW def-use: bare assignment is NOT consumption; consumed
    via return / call-arg / arithmetic is; py2 dialect tolerated (P1-3).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pwn宝"))

import comparator_v4 as C  # noqa: E402


def _op(op_id, kind, line, handle=None, alloc_req=None):
    return {"op_id": op_id, "kind": kind, "source_line": line,
            "source_call": f"call@L{line}", "handle": _v(handle),
            "allocator_request": _v(alloc_req)}


def _v(x):
    if x is None:
        return {"kind": "unknown", "reason": "x"}
    return {"kind": "concrete", "value": x, "source": str(x)}


def _step(op_id, n_chunks=0, fastbins=None, alloc_events=None, free_events=None):
    return {"step": None, "op_id": op_id, "n_chunks": n_chunks,
            "chunks": {}, "handles": [], "tcache": {}, "fastbins": fastbins or {},
            "smallbins": {}, "largebins": {}, "unsorted": [],
            "alloc_events": alloc_events or [], "free_events": free_events or [],
            "aborted": False, "warnings": []}


def _actual(ops, steps, run_id="run-test0001", tb=None, phys=None, canvas=None):
    return {
        "run_manifest": {"run_id": run_id},
        "analyzer": {"run_id": run_id, "valid": True, "recognizer_revision": "t",
                     "recognition": {}, "diagnostics": [],
                     "helper_contracts": [], "canonical_ops": ops},
        "target_behavior": {"run_id": run_id, "derivation": "t",
                            "per_op": tb if tb is not None else [
                                {"op_id": o["op_id"], "kind": o["kind"],
                                 "source_line": o["source_line"],
                                 "actions": ([{"action": "malloc", "request": o["allocator_request"]}]
                                             if o["kind"] == "alloc" else
                                             [{"action": "free", "target": o["handle"]}]
                                             if o["kind"] in ("free", "delete") else []),
                                 "internals_not_modeled": True} for o in ops]},
        "replay": {"run_id": run_id, "n_steps": len(steps), "steps": steps},
        "physical_memory": {"run_id": run_id, "steps": phys if phys is not None else [
            {"op_id": s["op_id"], "physical_objects": [{} for _ in range(s["n_chunks"])]}
            for s in steps]},
        "canvas_truth_model": {"run_id": run_id, "steps": canvas or []},
        "canvas_invariants": canvas if canvas is not None else [],
    }


EXPECTED = {
    "case_id": "synthetic",
    "helpers": [],
    "expected_operations": [
        {"source_line": 10, "source_call": "a()", "kind": "alloc",
         "arguments": {}, "allocator_request": "0x20"},
        {"source_line": 20, "source_call": "f()", "kind": "free",
         "arguments": {"arg0": 0}},
        {"source_line": 30, "source_call": "b()", "kind": "alloc",
         "arguments": {}, "allocator_request": "0x20"},
    ],
    "allocator_events": {"per_call": []},
    "machine_checks": [
        # after L30 free consumed the chunk: fastbins must be EMPTY again
        {"after_line": 30, "check": "bin_empty", "bin": "fastbins", "value": True,
         "fact": "fastbin empty after reuse"},
    ],
}


def test_t1_value_steps_do_not_shift_alignment():
    # heap ops op_001..3; snapshots contain init + VALUE steps interleaved.
    # op_002's snapshot still shows the freed chunk in fastbins; op_003's is
    # empty. A positional (+1 / index-based) mapping would read the wrong one.
    ops = [_op("op_001", "alloc", 10, alloc_req=0x20),
           _op("val_001", "value", 15),
           _op("op_002", "free", 20, handle=0),
           _op("val_002", "value", 25),
           _op("op_003", "alloc", 30, alloc_req=0x20)]
    steps = [
        _step("initial", n_chunks=0),
        _step("op_001", n_chunks=1,
              alloc_events=[{"kind": "alloc", "chunk": "A", "request_size": "0x20",
                             "chunk_size": "0x20", "source": "top"}]),
        _step("val_001", n_chunks=1),                      # value step (leak math)
        _step("op_002", n_chunks=1, fastbins={"0x20": ["A"]},
              free_events=[{"kind": "free", "chunk": "A", "destination_bin": "fastbin[0x20]"}]),
        _step("val_002", n_chunks=1, fastbins={"0x20": ["A"]}),
        _step("op_003", n_chunks=1, fastbins={},
              alloc_events=[{"kind": "alloc", "chunk": "B", "request_size": "0x20",
                             "chunk_size": "0x20", "source": "fastbin"}]),
    ]
    report = C.compare(EXPECTED, _actual(ops, steps), exp_source="")
    assert report["verdict"] == "MATCH", report.get("first_divergence")


def test_t1b_same_alignment_without_value_steps():
    ops = [_op("op_001", "alloc", 10, alloc_req=0x20),
           _op("val_001", "value", 15),
           _op("op_002", "free", 20, handle=0),
           _op("val_002", "value", 25),
           _op("op_003", "alloc", 30, alloc_req=0x20)]
    steps = [
        _step("initial"),
        _step("val_001", n_chunks=1),
        _step("op_001", n_chunks=1,
              alloc_events=[{"kind": "alloc", "chunk": "A", "request_size": "0x20",
                             "chunk_size": "0x20", "source": "top"}]),
        _step("op_002", n_chunks=1, fastbins={"0x20": ["A"]},
              free_events=[{"kind": "free", "chunk": "A", "destination_bin": "fastbin[0x20]"}]),
        _step("op_003", n_chunks=1, fastbins={},
              alloc_events=[{"kind": "alloc", "chunk": "B", "request_size": "0x20",
                             "chunk_size": "0x20", "source": "fastbin"}]),
    ]
    report = C.compare(EXPECTED, _actual(ops, steps))
    assert report["verdict"] == "MATCH"


def test_t2_mixed_run_ids_refused():
    ops = [_op("op_001", "alloc", 10, alloc_req=0x20)]
    steps = [_step("initial"), _step("op_001", n_chunks=1)]
    actual = _actual(ops, steps, run_id="run-aaa")
    actual["target_behavior"]["run_id"] = "run-bbb"   # stale artifact mixed in
    report = C.compare(EXPECTED, actual)
    assert report["verdict"] == "INCONCLUSIVE"
    assert report["first_divergence"]["layer"] == "RUN_IDENTITY"


def test_t3_target_behavior_and_allocator_are_separate_layers():
    # expected: L10 allocates TWICE (1:N truth); current pipeline derives once.
    truth = {
        "case_id": "synthetic-1n",
        "helpers": [],
        "expected_operations": [
            {"source_line": 10, "source_call": "create(0x18)", "kind": "alloc",
             "arguments": {}, "allocator_request": "0x18"},
        ],
        "allocator_events": {"per_call": [
            {"source_line": 10, "call": "create(0x18)",
             "events": [{"kind": "malloc", "request": "0x10"},
                        {"kind": "malloc", "request": "0x18"}]}]},
        "machine_checks": [],
    }
    ops = [_op("op_001", "alloc", 10, alloc_req=0x18)]
    steps = [_step("initial"),
             _step("op_001", n_chunks=1,
                   alloc_events=[{"kind": "alloc", "chunk": "A", "request_size": "0x18",
                                  "chunk_size": "0x20", "source": "top"}])]
    report = C.compare(truth, _actual(ops, steps))
    assert report["verdict"] == "DIVERGED"
    assert report["first_divergence"]["layer"] == "TARGET_BEHAVIOR"

    # same 1:1 target actions, but engine emitted the WRONG request:
    truth2 = dict(truth, allocator_events={"per_call": [
        {"source_line": 10, "call": "create(0x18)",
         "events": [{"kind": "malloc", "request": "0x18"}]}]})
    steps_bad = [_step("initial"),
                 _step("op_001", n_chunks=1,
                       alloc_events=[{"kind": "alloc", "chunk": "A", "request_size": "0x40",
                                      "chunk_size": "0x50", "source": "top"}])]
    report2 = C.compare(truth2, _actual(ops, steps_bad))
    assert report2["verdict"] == "DIVERGED"
    assert report2["first_divergence"]["layer"] == "ALLOCATOR"


def test_t4_defuse_output_dataflow():
    assigned_never_used = '''
def peek(idx):
    io.recvuntil("Choice:")
    io.sendline("3")
    io.recvuntil("Idx:")
    io.sendline(str(idx))
    blob = io.recv(64)
'''
    r = C.helper_body_output_dataflow(assigned_never_used, "peek")
    assert r["output_flows_strong"] == 0
    assert r["weak_assigned_unused"] == 1

    consumed_via_parse = '''
def peek(idx):
    io.sendline(str(idx))
    blob = io.recv(8)
    return u64(blob)
'''
    r2 = C.helper_body_output_dataflow(consumed_via_parse, "peek")
    assert r2["output_flows_strong"] >= 1

    returned_directly = '''
def peek(idx):
    io.sendline(str(idx))
    return io.recvline()
'''
    r3 = C.helper_body_output_dataflow(returned_directly, "peek")
    assert r3["output_flows_strong"] == 1

    py2_dialect = '''
def peek(idx):
    io.sendline(str(idx))
    blob = io.recv(8)
    print "got", u64(blob)
'''
    r4 = C.helper_body_output_dataflow(py2_dialect, "peek")
    assert r4["parse_ok"] is True and r4["found"] is True
    assert r4["output_flows_strong"] >= 1


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"PASS {name}")
    print("all infra tests passed")
