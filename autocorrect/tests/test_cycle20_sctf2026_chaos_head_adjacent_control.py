import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "autocorrect", ROOT / "pwncraft"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from challenge_intake import load_splits, split_for_case
from pwncraft.features.audit.reviewed_chains import AdjacentObjectPolicy, derive_adjacent_object_chain

CASE_ID = "memory_write-sctf-2026-chaos-head-576f58ec"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle20.json"


def _truth() -> dict:
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _policy() -> AdjacentObjectPolicy:
    return AdjacentObjectPolicy(**_truth()["reviewed_adjacent_object_policy"])


def test_case_is_train_and_truth_is_locked_to_official_materials() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"
    truth = _truth()
    assert truth["truth_lock"]["truth_revision"] == 1
    assert truth["materials"]["official_exp_git_blob_sha1"] == \
        "576f58ec3939bfdef9b806263f65e98f9b0bbb1b"
    assert truth["materials"]["official_writeup_git_blob_sha1"] == \
        "7a033c7fb9c5e684dfcb78cd8b4a1c457d1a086a"


def test_reviewed_geometry_reaches_route_sink_for_leak_and_overwrite() -> None:
    chain = derive_adjacent_object_chain(_policy(), planned_input_length=0x900)
    computed = chain["computed"]
    assert computed["dump_length"] == 0x840
    assert computed["adjacent_field_end"] == 0x838
    assert computed["leak_reaches_field"] is True
    assert computed["capacity_survives_clear"] is True
    assert computed["input_allowed_after_clear"] is True
    assert computed["write_reaches_field"] is True
    assert computed["indirect_control_transfer"] is True
    kinds = {item["kind"] for item in chain["facts"]}
    assert {
        "adjacent_object_read_leak",
        "corrupted_capacity_persists_across_clear",
        "adjacent_function_pointer_overwrite",
        "indirect_control_transfer_via_overwritten_field",
    } <= kinds
    assert chain["state"] == "derived_static"
    assert chain["runtime_observed"] is False


def test_clear_that_repairs_capacity_blocks_post_clear_overwrite() -> None:
    chain = derive_adjacent_object_chain(
        replace(_policy(), clear_preserves_capacity=False), planned_input_length=0x900
    )
    assert chain["computed"]["input_allowed_after_clear"] is False
    assert chain["computed"]["write_reaches_field"] is False
    assert chain["computed"]["indirect_control_transfer"] is False


def test_short_payload_does_not_reach_route_sink_even_when_capacity_is_large() -> None:
    chain = derive_adjacent_object_chain(_policy(), planned_input_length=0x800)
    assert chain["computed"]["input_allowed_after_clear"] is True
    assert chain["computed"]["write_reaches_field"] is False
    assert chain["computed"]["indirect_control_transfer"] is False


def test_short_dump_cap_blocks_adjacent_read_claim() -> None:
    chain = derive_adjacent_object_chain(
        replace(_policy(), dump_cap=0x800), planned_input_length=0x900
    )
    assert chain["computed"]["leak_reaches_field"] is False
