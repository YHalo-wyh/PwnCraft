from pwncraft.features.semantic_runtime import observations_from_fmt, observations_from_heap_trace, observations_from_synth


def test_synth_runtime_offset_and_verified_shell_become_observations():
    rows = observations_from_synth({
        "runtime": {"offset": 72, "method": "saved_rbp", "evidence": ["gdb hit"]},
        "verification": {"status": "VERIFIED_SHELL", "summary": "marker", "evidence": []},
    })
    assert rows[0]["primitives"] == ["RIP_control"]
    assert rows[1]["primitives"] == ["code_execution"]


def test_fmt_probe_only_promotes_controlled_probe():
    assert observations_from_fmt({"controlled": False}) == []
    rows = observations_from_fmt({"controlled": True, "probe": "%p", "evidence": ["echo"]})
    assert rows[0]["vuln_type"] == "format_string"


def test_heap_trace_exposes_uaf_write_and_overlap_primitives():
    rows = observations_from_heap_trace({
        "events": [{"op": "free", "index": 0}, {"op": "add", "index": 1}],
        "alias": True, "stale_read": True, "write_target": "chunk[1]",
        "overlap": True, "evidence": ["gdb heap replay"],
    })
    assert {"uaf", "heap_overlap"} <= {row["vuln_type"] for row in rows}
    assert "UAF_write" in rows[0]["primitives"]
