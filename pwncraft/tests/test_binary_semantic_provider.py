import pytest

from pwncraft.core.binary_semantic_provider import (
    SCHEMA_VERSION,
    evidence_for_function,
    load_binary_semantic_snapshot,
    project_semantic_evidence,
)


def _payload():
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": "idalib-mcp-export",
        "binary_sha256": "ab" * 32,
        "records": [
            {
                "evidence_id": "ev-1",
                "kind": "CALL",
                "function_address": "0x401000",
                "address": "0x401020",
                "backend": "ida-decompile",
                "statement": "free(v3)",
                "operands": {"callee": "free", "arg0": "v3"},
                "provenance": "IDA_DECOMPILER",
                "source_span": {"line": 12},
            },
            {
                "evidence_id": "ev-2",
                "kind": "CALL_INDIRECT",
                "function_address": 0x401000,
                "address": 0x401040,
                "backend": "ida-disasm",
                "statement": "call rax",
                "operands": {"target": "rax"},
                "provenance": "IDA_DISASM",
            },
        ],
    }


def test_binary_semantic_snapshot_preserves_exact_addresses_and_provenance():
    snapshot = load_binary_semantic_snapshot(_payload())
    facts = evidence_for_function(snapshot, "0x401000")
    assert [fact["evidence_id"] for fact in facts] == ["ev-1", "ev-2"]
    projected = project_semantic_evidence(snapshot)
    assert projected[0]["address"] == "0x401020"
    assert projected[0]["binary_sha256"] == "ab" * 32
    assert projected[0]["provider"] == "idalib-mcp-export"


def test_binary_semantic_snapshot_rejects_name_only_or_unanchored_evidence():
    payload = _payload()
    payload["records"][0].pop("address")
    with pytest.raises((ValueError, TypeError)):
        load_binary_semantic_snapshot(payload)

    payload = _payload()
    payload["records"][0]["kind"] = "FUNCTION_NAME_LOOKS_LIKE_FREE"
    with pytest.raises(ValueError):
        load_binary_semantic_snapshot(payload)


def test_binary_semantic_snapshot_rejects_duplicate_evidence_ids():
    payload = _payload()
    payload["records"].append(dict(payload["records"][0]))
    with pytest.raises(ValueError):
        load_binary_semantic_snapshot(payload)
