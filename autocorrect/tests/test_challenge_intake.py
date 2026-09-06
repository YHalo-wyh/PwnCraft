import json
import sys
from pathlib import Path

import pytest

AUTOCORRECT = Path(__file__).resolve().parents[1]
if str(AUTOCORRECT) not in sys.path:
    sys.path.insert(0, str(AUTOCORRECT))

from challenge_intake import assert_allowed, decide_case, load_splits


def _case(tmp_path: Path, case_id: str, *, ready: bool = True) -> Path:
    case_dir = tmp_path / case_id
    case_dir.mkdir()
    manifest = {
        "case_id": case_id,
        "technique": "stack_rop",
        "target": {
            "arch": "amd64",
            "binary_sha256": "a" * 64 if ready else "",
        },
        "exp_analysis": {
            "entry_file": {"rel": "exp.py", "role": "python", "size": 12}
            if ready else None,
        },
        "quality": {"tier": "GOLD"},
    }
    (case_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return case_dir


def _splits(tmp_path: Path, **members: list[str]) -> Path:
    payload = {name: [] for name in ("train", "validation", "frozen_test")}
    for split, case_ids in members.items():
        payload[split] = [{"case_id": case_id, "cluster": "synthetic"} for case_id in case_ids]
    path = tmp_path / "splits.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_train_case_can_drive_patch_feedback(tmp_path: Path) -> None:
    case_dir = _case(tmp_path, "stack-train")
    splits = _splits(tmp_path, train=["stack-train"])
    decision = decide_case(case_dir, purpose="train", splits_path=splits)
    assert decision.allowed
    assert decision.split == "train"
    assert decision.domain == "stack"


def test_validation_case_is_evaluate_only(tmp_path: Path) -> None:
    case_dir = _case(tmp_path, "stack-validation")
    splits = _splits(tmp_path, validation=["stack-validation"])
    assert not decide_case(case_dir, purpose="train", splits_path=splits).allowed
    assert decide_case(case_dir, purpose="validate", splits_path=splits).allowed


def test_frozen_case_never_enters_training_lane(tmp_path: Path) -> None:
    case_dir = _case(tmp_path, "stack-frozen")
    splits = _splits(tmp_path, frozen_test=["stack-frozen"])
    assert not decide_case(case_dir, purpose="train", splits_path=splits).allowed
    assert not decide_case(case_dir, purpose="validate", splits_path=splits).allowed
    assert decide_case(case_dir, purpose="build_truth", splits_path=splits).allowed
    assert decide_case(case_dir, purpose="frozen_evaluate", splits_path=splits).allowed
    with pytest.raises(PermissionError, match="case intake blocked"):
        assert_allowed(case_dir, purpose="train", splits_path=splits)


def test_unsplit_case_is_blocked_until_registered(tmp_path: Path) -> None:
    case_dir = _case(tmp_path, "fresh-user-case")
    splits = _splits(tmp_path)
    decision = decide_case(case_dir, purpose="train", splits_path=splits)
    assert not decision.allowed
    assert decision.split == "unsplit"
    assert "禁止" in decision.reason or "split" in decision.reason


def test_missing_material_blocks_even_train_split(tmp_path: Path) -> None:
    case_dir = _case(tmp_path, "incomplete", ready=False)
    splits = _splits(tmp_path, train=["incomplete"])
    decision = decide_case(case_dir, purpose="train", splits_path=splits)
    assert not decision.allowed
    assert not decision.material_ready
    assert decision.gaps


def test_duplicate_split_membership_is_rejected(tmp_path: Path) -> None:
    splits = _splits(tmp_path, train=["duplicate"], validation=["duplicate"])
    with pytest.raises(ValueError, match="同时属于"):
        load_splits(splits)
