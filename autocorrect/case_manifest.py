#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CaseManifest 统一入口 (VNext M1 跨域接入, 阶段 1)。

两种既有入口格式归一：
  heap (batch-1/2): exp_analysis.entry_file = str (repo 相对路径)
  stack/fmt (batch-3): exp_analysis.entry_file = {rel, role, size} dict 或
                       list[dict] 或 None (缺失)

产出 CaseMaterial：领域、入口状态 (ok|ambiguous|missing)、材料角色、架构、
libc 有无、material_readiness 与 gaps。空入口进入材料待补队列，不进评测。

Deterministic-First: 只读 manifest 与文件系统事实，不做推断。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

TECHNIQUE_TO_DOMAIN = {
    "heap": "heap",
    "stack_rop": "stack",
    "fmtstr": "fmt",
    "fsop": "fmt",
    "race": "future",
    "kernel": "future",
    "arch_excluded": "future",
    "non_pwn": "non_pwn",
    "other": "non_pwn",
}

# 各领域评测所需材料 (阶段 1 契约默认; 可被 evaluation_contract 覆盖)
DOMAIN_REQUIRED = {
    "heap": ["binary", "exp"],
    "stack": ["binary", "exp"],
    "fmt": ["binary", "exp"],
    "future": ["binary"],
    "non_pwn": [],
}


@dataclass
class CaseMaterial:
    case_id: str
    technique: str
    domain: str
    tier: str
    arch: str
    entry_status: str            # ok | ambiguous | missing
    entry_candidates: list[dict] = field(default_factory=list)
    binary_sha256: str = ""
    libc_present: bool = False
    source_present: bool = False
    material_readiness: bool = False
    gaps: list[str] = field(default_factory=list)
    case_dir: str = ""

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id, "technique": self.technique,
            "domain": self.domain, "tier": self.tier, "arch": self.arch,
            "entry_status": self.entry_status,
            "entry_candidates": [
                {k: v for k, v in c.items() if k in ("rel", "path", "name", "size")}
                for c in self.entry_candidates],
            "binary_sha256": self.binary_sha256,
            "libc_present": self.libc_present,
            "source_present": self.source_present,
            "material_readiness": self.material_readiness,
            "gaps": list(self.gaps),
            "case_dir": self.case_dir,
        }


def _entry_candidates(manifest: dict) -> tuple[str, list[dict]]:
    """归一 entry_file 的三种形态 → (status, candidates[绝对路径建议])。"""
    ea = manifest.get("exp_analysis") or {}
    ef = ea.get("entry_file")
    if isinstance(ef, str) and ef.strip():
        return "ok", [{"rel": ef.strip()}]
    if isinstance(ef, dict) and ef:
        return "ok", [dict(ef)]
    if isinstance(ef, list):
        py = [c for c in ef if isinstance(c, dict)
              and str(c.get("rel", c.get("path", ""))).endswith(".py")]
        if len(py) == 1:
            return "ok", py
        if len(py) > 1:
            return "ambiguous", py
        return "missing", []
    return "missing", []


def load_case_material(case_dir: str | Path) -> CaseMaterial | None:
    case_dir = Path(case_dir)
    mf_path = case_dir / "manifest.json"
    if not mf_path.exists():
        return None
    manifest = json.loads(mf_path.read_text(encoding="utf-8"))
    technique = str(manifest.get("technique")
                    or ("heap" if "heap" in str(manifest.get("source", {})).lower()
                        else "other"))
    domain = TECHNIQUE_TO_DOMAIN.get(technique, "non_pwn")
    status, candidates = _entry_candidates(manifest)
    target = manifest.get("target") or {}
    gaps: list[str] = []
    required = DOMAIN_REQUIRED.get(domain, ["binary"])
    has_binary = bool(target.get("binary_sha256"))
    has_exp = status == "ok"
    libc_present = bool(target.get("libc_sha256"))
    if "binary" in required and not has_binary:
        gaps.append("binary missing")
    if "exp" in required and not has_exp:
        gaps.append("exp entry missing")
        if status == "ambiguous":
            gaps[-1] = "exp entry ambiguous (多个候选)"
    material_ready = not gaps
    return CaseMaterial(
        case_id=str(manifest.get("case_id") or case_dir.name),
        technique=technique, domain=domain,
        tier=str((manifest.get("quality") or {}).get("tier") or ""),
        arch=str(target.get("arch") or "amd64"),
        entry_status=status, entry_candidates=candidates,
        binary_sha256=str(target.get("binary_sha256") or ""),
        libc_present=libc_present,
        source_present=any((case_dir / "original" / "challenge").glob("*.c"))
        if (case_dir / "original" / "challenge").exists() else False,
        material_readiness=material_ready, gaps=gaps,
        case_dir=str(case_dir),
    )


def inventory(corpus_dir: str | Path, review_dir: str | Path) -> dict:
    """清点全部案例 (阶段 3 材料治理的 M1 前置)。"""
    rows = []
    for base in (Path(corpus_dir), Path(review_dir)):
        if not base.exists():
            continue
        for case_dir in sorted(base.iterdir()):
            if not (case_dir / "manifest.json").exists():
                continue
            material = load_case_material(case_dir)
            if material is not None:
                material.domain = material.domain
                rows.append(material)
    by_domain: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for r in rows:
        by_domain[r.domain] = by_domain.get(r.domain, 0) + 1
        by_status[r.entry_status] = by_status.get(r.entry_status, 0) + 1
    return {
        "total": len(rows),
        "by_domain": by_domain,
        "by_entry_status": by_status,
        "ready": sum(1 for r in rows if r.material_readiness),
        "cases": [r.to_dict() for r in rows],
    }
