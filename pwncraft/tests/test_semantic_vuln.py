from pwncraft.features.semantic_vuln import from_vuln_report


def test_semantic_report_promotes_stack_overflow_to_rip_control():
    result = from_vuln_report({"points": [{
        "category": "memory_corruption", "verdict": "overflow_confirmed",
        "severity": "high", "confidence": "proven",
        "function": "vuln", "vaddr": "0x4011c1",
        "reason": "input reaches saved rbp", "evidence": ["read len 0x100"]
    }]})
    finding = result["findings"][0]
    assert finding["vuln_type"] == "stack_overflow"
    assert "RIP_control" in finding["primitives"]
    assert finding["confidence"] == "proven"


def test_runtime_observation_is_separate_and_preserved():
    result = from_vuln_report({"points": []}, runtime_observations=[{
        "category": "heap_lifetime", "verdict": "uaf_confirmed",
        "primitives": ["UAF_write"], "evidence": ["gdb replay"]
    }])
    assert result["findings"][0]["source"] == "dynamic"
    assert "UAF_write" in result["primitives"]
