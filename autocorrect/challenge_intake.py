#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Split-safe intake gate for real Pwn challenge training.

The corpus is now cross-domain, but a real challenge must never become patch
feedback merely because it is present on disk.  This module makes the
train/validation/frozen_test contract executable and checks material readiness
before any domain adapter is allowed to run.

Deterministic-First rules:
- a case must belong to exactly one split;
- training may consume only ``train`` cases;
- validation cases are evaluate-only and cannot drive patches;
- frozen_test cases are untouched until the explicit frozen evaluation stage;
- an unsplit or material-incomplete case is BLOCKED, never guessed into a lane.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from case_manifest import CaseMaterial, load_case_material

HERE = Path(__file__).resolve().parent
DEFAULT_SPLITS = HERE / "splits.json"
VALID_SPLITS = ("train", "validation", "frozen_test")
VALID_PURPOSES = ("build_truth", "train", "validate", "frozen_evaluate")


@dataclass(frozen=True)
class IntakeDecision:
    case_id: str
    split: str
    purpose: str
    allowed: bool
    material_ready: bool
    domain: str = ""
    reason: str = ""
    gaps: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "split": self.split,
            "purpose": self.purpose,
            "allowed": self.allowed,
            "material_ready": self.material_ready,
            "domain": self.domain,
            "reason": self.reason,
            "gaps": list(self.gaps),
        }


def load_splits(path: str | Path = DEFAULT_SPLITS) -> dict[str, list[dict]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    result: dict[str, list[dict]] = {}
    seen: dict[str, str] = {}
    for split in VALID_SPLITS:
        items = raw.get(split, [])
        if not isinstance(items, list):
            raise ValueError(f"split {split!r} 必须是数组")
        normalized: list[dict] = []
        for item in items:
            if not isinstance(item, Mapping):
                raise ValueError(f"split {split!r} 含非对象条目")
            case_id = str(item.get("case_id") or "").strip()
            if not case_id:
                raise ValueError(f"split {split!r} 含空 case_id")
            previous = seen.get(case_id)
            if previous is not None:
                raise ValueError(f"case {case_id!r} 同时属于 {previous} 与 {split}")
            seen[case_id] = split
            normalized.append(dict(item))
        result[split] = normalized
    return result


def split_for_case(case_id: str, splits: Mapping[str, list[dict]]) -> str:
    target = str(case_id or "").strip()
    matches = []
    for split in VALID_SPLITS:
        for item in splits.get(split, []):
            if str(item.get("case_id") or "").strip() == target:
                matches.append(split)
    if len(matches) > 1:
        raise ValueError(f"case {target!r} 出现在多个 split: {matches}")
    return matches[0] if matches else "unsplit"


def _policy(split: str, purpose: str) -> tuple[bool, str]:
    if purpose == "build_truth":
        if split in VALID_SPLITS:
            return True, "clean-room truth 可在任何已注册 split 上建立；不得读取 PwnCraft 输出"
        return False, "建立 truth 前必须先注册 split"
    if purpose == "train":
        return (
            (True, "train split 可作为 first-divergence/patch feedback")
            if split == "train"
            else (False, f"{split} 不是训练 split；禁止用其结果驱动 patch")
        )
    if purpose == "validate":
        return (
            (True, "validation split 仅用于泛化评估，不驱动 patch")
            if split == "validation"
            else (False, f"validate 只接受 validation split，当前为 {split}")
        )
    if purpose == "frozen_evaluate":
        return (
            (True, "frozen_test 仅在训练/验证完成后做最终评估")
            if split == "frozen_test"
            else (False, f"frozen_evaluate 只接受 frozen_test，当前为 {split}")
        )
    raise ValueError(f"未知 intake purpose: {purpose!r}")


def decide_case(
    case_dir: str | Path,
    *,
    purpose: str,
    splits_path: str | Path = DEFAULT_SPLITS,
) -> IntakeDecision:
    purpose = str(purpose or "").strip()
    if purpose not in VALID_PURPOSES:
        raise ValueError(f"未知 intake purpose: {purpose!r}")
    material: CaseMaterial | None = load_case_material(case_dir)
    if material is None:
        return IntakeDecision(
            case_id=Path(case_dir).name,
            split="unsplit",
            purpose=purpose,
            allowed=False,
            material_ready=False,
            reason="manifest.json 缺失；不能进入训练/评估",
            gaps=("manifest missing",),
        )
    splits = load_splits(splits_path)
    split = split_for_case(material.case_id, splits)
    policy_allowed, policy_reason = _policy(split, purpose)
    if not material.material_readiness:
        return IntakeDecision(
            case_id=material.case_id,
            split=split,
            purpose=purpose,
            allowed=False,
            material_ready=False,
            domain=material.domain,
            reason="材料不完整；保持 BLOCKED，不以缺失信息推断 truth",
            gaps=tuple(material.gaps),
        )
    return IntakeDecision(
        case_id=material.case_id,
        split=split,
        purpose=purpose,
        allowed=policy_allowed,
        material_ready=True,
        domain=material.domain,
        reason=policy_reason,
        gaps=(),
    )


def assert_allowed(
    case_dir: str | Path,
    *,
    purpose: str,
    splits_path: str | Path = DEFAULT_SPLITS,
) -> IntakeDecision:
    decision = decide_case(case_dir, purpose=purpose, splits_path=splits_path)
    if not decision.allowed:
        raise PermissionError(
            f"case intake blocked: {decision.case_id} · {decision.purpose} · "
            f"split={decision.split} · {decision.reason}"
        )
    return decision
