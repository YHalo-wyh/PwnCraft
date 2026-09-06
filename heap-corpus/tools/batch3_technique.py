#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch-3: 全 pwn 技术栈语料扩充 (owner 指令: 不只是堆题, 栈的各种利用都要有).

从已克隆仓库的 candidates JSONL 里按技术分类重判:
  stack_rop / fmtstr / fsop / race  → GOLD(binary+exp+libc) / SILVER(binary+exp) / BRONZE
  kernel / arch(arm,mips)           → BRONZE 索引 (模拟器范围外, 不作监督样本)
  heap                              → batch-1/2 已处理, 本轮只做 sha 去重核对
去重: binary sha 全局唯一 (batch-1 GOLD + 本轮), 10cks 与 ctf-wiki 镜像重叠自动剔除。
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AC = ROOT / "heap-corpus"

TECHNIQUE_RULES = [
    ("other", "non_pwn"),       # ctf-wiki other/: android 逆向 / crypto 等, 非 pwn
    ("android", "non_pwn"),
    ("crypto", "non_pwn"),
    ("reverse", "non_pwn"),
    ("kernel", "kernel"),
    ("race-condition", "race"),
    ("io-file", "fsop"),
    ("fmtstr", "fmtstr"),
    ("stackoverflow", "stack_rop"),
    ("arm", "arch_excluded"),
    ("mips", "arch_excluded"),
    ("heap", "heap"),
]


def technique_of(unit: str) -> str:
    for marker, tech in TECHNIQUE_RULES:
        if f"/{marker}/" in f"/{unit}/" or unit.startswith(marker):
            return tech
    return "other"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(str(p), "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    corpus = AC / "corpus"
    review = AC / "review_queue"
    seen_sha: dict[str, str] = {}
    for mf in list(corpus.glob("*/manifest.json")) + list(review.glob("*/manifest.json")):
        m = json.loads(mf.read_text(encoding="utf-8"))
        b = (m.get("target") or {}).get("binary_sha256")
        if b:
            seen_sha[b] = m["case_id"]

    report = {"batch": "batch-3 (全 pwn 技术栈扩充)", "date": "2026-09-05",
              "added": [], "already_present": [], "duplicates": [],
              "bronze": [], "skipped": []}
    tier_counts: dict[str, int] = {}
    tech_counts: dict[str, int] = {}

    for cand_file in ("candidates/ctfwiki.jsonl", "candidates/10cks.jsonl"):
        for line in (AC / cand_file).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            unit = r["unit"]
            tech = technique_of(unit)
            if tech == "heap":
                continue  # batch-1/2 已处理
            if tech in ("arch_excluded", "non_pwn"):
                continue  # 非 amd64 用户态 / 非 pwn 类别: 不入训练语料
            repo = r["repo"]
            stage = Path(repo["staging_path"])
            files = r["files"]
            binaries = files.get("binaries") or []
            pys = files.get("python") or []
            libcs = files.get("libc") or []
            has_bin = bool(binaries)
            has_exp = bool(pys)
            has_libc = bool(libcs)
            if not (has_bin or has_exp):
                continue
            if r.get("reject") == "KERNEL" or tech == "kernel":
                report["bronze"].append({"unit": unit, "tech": tech,
                                         "reason": "kernel: simulator 范围外, 仅索引"})
                continue
            if not has_bin:
                report["bronze"].append({"unit": unit, "tech": tech,
                                         "reason": "NO_BINARY"})
                continue
            binary = binaries[0]
            bpath = stage / binary["rel"]
            if not bpath.exists():
                report["skipped"].append({"unit": unit, "reason": "binary missing"})
                continue
            sha = sha256_file(bpath)
            slug = unit.replace("/", "-")
            would_be_case_id = f"{tech}-{slug[:60]}-{sha[:8]}"
            if sha in seen_sha:
                prior = seen_sha[sha]
                kind = ("already-present" if prior == would_be_case_id
                        else "duplicate")
                (report["already_present" if kind == "already-present" else "duplicates"]
                 .append({"unit": unit, "tech": tech,
                          "case_id": prior if kind == "already-present" else None,
                          "dup_of": prior if kind == "duplicate" else None}))
                continue
            seen_sha[sha] = unit
            exp_file = next((p for p in pys
                             if any(k in Path(p["rel"]).name.lower()
                                    for k in ("exp", "solve", "payload", "pwn"))), None)
            tier = ("GOLD" if (has_bin and has_exp and has_libc)
                    else "SILVER" if (has_bin and has_exp) else "BRONZE")
            if tier == "BRONZE":
                report["bronze"].append({"unit": unit, "tech": tech,
                                         "reason": "binary without exp"})
                continue

            slug = unit.replace("/", "-")
            case_id = f"{tech}-{slug[:60]}-{sha[:8]}"
            bundle = (corpus if tier == "GOLD" else review) / case_id
            (bundle / "original" / "challenge").mkdir(parents=True, exist_ok=True)
            (bundle / "original" / "solution").mkdir(parents=True, exist_ok=True)
            for f in binaries + libcs + files.get("source") or []:
                src = stage / f["rel"]
                if src.exists():
                    shutil.copyfile(str(src), str(bundle / "original" / "challenge" / f["rel"].replace("/", "_")))
            for f in pys:
                src = stage / f["rel"]
                if src.exists():
                    shutil.copyfile(str(src), str(bundle / "original" / "solution" / Path(f["rel"]).name))
            manifest = {
                "schema_version": "1.0",
                "case_id": case_id,
                "source": {"repository_url": repo["url"],
                           "commit_sha": repo.get("commit_sha"),
                           "challenge_path": unit, "ctf": None,
                           "year": None, "challenge_name": Path(unit).name,
                           "license": repo.get("license"),
                           "source_class": repo.get("source_class")},
                "target": {"arch": (binary.get("elf") or {}).get("arch", "amd64"),
                           "os": "linux", "binary_sha256": sha,
                           "libc_sha256": None, "ld_sha256": None},
                "glibc": {"version": None, "confidence": "LOW", "evidence": []},
                "technique": tech,
                "heap": r.get("heap", {}),
                "files": [], "exp_analysis": {"entry_file": exp_file,
                                              "correctness": "UNVERIFIED"},
                "quality": {"tier": tier,
                            "issues": ([] if has_libc else
                                       ["缺 libc (SILVER)" if tier == "SILVER" else "缺 exp"])},
            }
            (bundle / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            entry = {"case_id": case_id, "tier": tier, "technique": tech,
                     "binary_sha256": sha[:12],
                     "exp": Path(exp_file["rel"]).name if exp_file else None}
            report["added"].append(entry)
            tier_counts[tier] = tier_counts.get(tier, 0) + 1
            tech_counts[tech] = tech_counts.get(tech, 0) + 1

    report["summary"] = {"tier_counts": tier_counts, "technique_counts": tech_counts,
                         "global_unique_binaries": len(seen_sha)}
    (AC / "collection_report_batch3.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("tier:", tier_counts)
    print("tech:", tech_counts)
    print("duplicates:", len(report["duplicates"]),
          "| bronze:", len(report["bronze"]), "| skipped:", len(report["skipped"]))


if __name__ == "__main__":
    main()
