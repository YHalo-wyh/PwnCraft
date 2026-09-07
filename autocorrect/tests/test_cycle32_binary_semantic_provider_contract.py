from pwncraft.core.binary_semantic_provider import (
    SCHEMA_VERSION,
    load_binary_semantic_snapshot,
    project_semantic_evidence,
)


def test_cycle32_ida_provider_contract_keeps_semantics_address_anchored():
    payload = {
        "schema_version": SCHEMA_VERSION,
        "provider": "idalib-mcp-export",
        "binary_sha256": "42" * 32,
        "records": [{
            "evidence_id": "call-1",
            "kind": "CALL_INDIRECT",
            "function_address": "0x401000",
            "address": "0x40104a",
            "backend": "ida-disasm",
            "statement": "call rax",
            "operands": {"target": "rax"},
            "provenance": "IDA_DISASM",
        }],
    }
    snapshot = load_binary_semantic_snapshot(payload)
    projected = project_semantic_evidence(snapshot)
    assert projected[0]["function_address"] == "0x401000"
    assert projected[0]["address"] == "0x40104a"
    assert projected[0]["kind"] == "CALL_INDIRECT"
    assert projected[0]["provider"] == "idalib-mcp-export"
