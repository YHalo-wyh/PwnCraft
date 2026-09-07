import json
from pathlib import Path

from pwncraft.features.audit.reviewed_allocator_control import (
    AdjacentChunkMetadataPolicy,
    derive_adjacent_chunk_metadata_overwrite,
)


ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "cases" / "heap-sctf-2026-heapmage-9765b15f" / "expected_truth_cycle23.json"


def _truth():
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _policy():
    raw = dict(_truth()["reviewed_adjacent_metadata_policy"])
    raw.pop("provenance", None)
    raw["name"] = "sctf-heapmage-reviewed-adjacent-metadata"
    raw["metadata_fields"] = tuple(tuple(item) for item in raw["metadata_fields"])
    return AdjacentChunkMetadataPolicy(**raw)


def test_cycle23_truth_recovers_exact_full_write_coverage_and_constraints():
    result = derive_adjacent_chunk_metadata_overwrite(_policy(), write_length=0xF0)
    assert result is not None
    assert result["allocator"] == {"family": "glibc", "version": "2.39"}
    assert result["overflow_length"] == 0x30
    assert [item["field"] for item in result["covered_fields"]] == [
        "prev_size", "size", "fd", "bk", "fd_nextsize", "bk_nextsize"
    ]
    assert [item["kind"] for item in result["constraints"]] == [
        "masked_size_interval", "pointer_must_reference_heap_range"
    ]


def test_cycle23_in_bounds_edit_is_not_reported_as_overflow():
    assert derive_adjacent_chunk_metadata_overwrite(_policy(), write_length=0xC0) is None


def test_cycle23_bounded_metadata_write_is_not_promoted_to_arbitrary_write_or_largebin():
    result = derive_adjacent_chunk_metadata_overwrite(_policy(), write_length=0xF0)
    assert result is not None
    text = json.dumps(result, ensure_ascii=False).lower()
    assert "arbitrary-address write" in text
    assert "largebin attack" not in text
