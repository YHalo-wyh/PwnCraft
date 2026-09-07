import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "autocorrect", ROOT / "pwncraft"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from challenge_intake import load_splits, split_for_case
from pwncraft.features.audit.reviewed_chains import AliasHelperPolicy, derive_alias_release_hazard

CASE_ID = "heap-sctf-2026-ubw-1b3b161e"
TRUTH = ROOT / "autocorrect" / "cases" / CASE_ID / "expected_truth_cycle21.json"


def _truth() -> dict:
    return json.loads(TRUTH.read_text(encoding="utf-8"))


def _policy() -> AliasHelperPolicy:
    raw = dict(_truth()["reviewed_alias_helper_policy"])
    raw["alias_parameter_indexes"] = tuple(raw["alias_parameter_indexes"])
    return AliasHelperPolicy(**raw)


def test_case_is_train_and_truth_is_locked_to_official_exp_and_writeup() -> None:
    assert split_for_case(CASE_ID, load_splits()) == "train"
    truth = _truth()
    assert truth["truth_lock"]["truth_revision"] == 1
    assert truth["materials"]["official_exp_git_blob_sha1"] == \
        "1b3b161e9c96210b8d7769a3f5234c999061078b"
    assert truth["materials"]["official_writeup_git_blob_sha1"] == \
        "88396d49a8a3bab8c71f9120ef48a5267e9ff153"


def test_official_merge_zero_zero_derives_conditional_stale_read_and_double_release() -> None:
    relation = derive_alias_release_hazard("merge(0, 0)", _policy())
    assert relation is not None
    assert relation["aliased_expression"] == "0"
    assert relation["conditional_double_release"] is True
    kinds = {item["kind"] for item in relation["facts"]}
    assert {
        "same_argument_alias",
        "conditional_realloc_release",
        "conditional_stale_read_after_realloc",
        "conditional_double_release_same_identity",
    } <= kinds
    assert relation["state"] == "derived_static"
    assert relation["runtime_observed"] is False


def test_distinct_merge_arguments_do_not_become_aliases() -> None:
    assert derive_alias_release_hazard("merge(0, 1)", _policy()) is None
    assert derive_alias_release_hazard("merge(dst, src)", _policy()) is None


def test_without_reviewed_realloc_move_release_only_alias_fact_remains() -> None:
    relation = derive_alias_release_hazard(
        "merge(idx, idx)", replace(_policy(), realloc_may_move_and_free_old=False)
    )
    assert relation is not None
    assert relation["conditional_double_release"] is False
    assert {item["kind"] for item in relation["facts"]} == {"same_argument_alias"}


def test_wrong_helper_name_does_not_inherit_ubw_merge_semantics() -> None:
    assert derive_alias_release_hazard("combine(0, 0)", _policy()) is None
