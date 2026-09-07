import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "autocorrect", ROOT / "pwncraft"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from challenge_intake import load_splits, split_for_case
from pwncraft.features.audit.reviewed_chains import (
    AdditiveControlTargetPolicy,
    derive_additive_control_plan,
)

CASE_ID = "memory_write-sctf-2026-slang-a31e8aa0"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle19.json"


def _truth() -> dict:
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _policy() -> AdditiveControlTargetPolicy:
    raw = _truth()["reviewed_control_target_policy"]
    return AdditiveControlTargetPolicy(**raw)


def _primitive(**changes) -> dict:
    raw = dict(_truth()["upstream_accepted_primitive"])
    raw.pop("address_hex", None)
    raw.pop("truth_source", None)
    raw["domain"] = "memory_write"
    raw["evidence"] = [{"kind": "indexed_additive_write", "operation": "add"}]
    raw.update(changes)
    return raw


def test_truth_revision_six_uses_reviewed_relative_delta_without_invented_offsets() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"
    truth = _truth()
    assert truth["truth_lock"]["truth_revision"] == 6
    assert truth["truth_lock"]["supersedes"] == \
        "truth-sctf2026-slang-forged-vec-additive-write-v5"
    policy = truth["reviewed_control_target_policy"]
    assert policy["reviewed_symbol_delta"] == -205200
    assert "current_symbol_offset" not in policy
    assert "desired_symbol_offset" not in policy


def test_official_additive_write_composes_into_static_puts_to_system_control_plan() -> None:
    plan = derive_additive_control_plan(_primitive(), _policy())
    assert plan is not None
    assert plan["target"]["address"] == 0x404018
    assert plan["target"]["symbol"] == "puts@GOT"
    assert plan["value_transition"]["current_symbol"] == "puts"
    assert plan["value_transition"]["desired_symbol"] == "system"
    assert plan["value_transition"]["required_delta"] == -205200
    assert plan["value_transition"]["delta_source"] == "reviewed_relative_delta"
    assert "current_symbol_offset" not in plan["value_transition"]
    assert plan["effect"] == "puts@GOT: puts -> system"
    assert plan["state"] == "derived_static"
    assert plan["runtime_observed"] is False


def test_wrong_delta_or_unresolved_current_value_blocks_control_plan() -> None:
    assert derive_additive_control_plan(_primitive(delta=-1), _policy()) is None
    assert derive_additive_control_plan(
        _primitive(), replace(_policy(), current_value_resolved=False)
    ) is None


def test_mismatched_target_address_or_nonfixed_target_blocks_control_plan() -> None:
    assert derive_additive_control_plan(_primitive(address=0x404020), _policy()) is None
    assert derive_additive_control_plan(
        _primitive(), replace(_policy(), fixed_address=False)
    ) is None
