#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M3 栈金标准断言集 (VNext.2/阶段 2 课程 2-3)。

对栈领域 GOLD/SILVER 案例的二进制跑 objdump → trace_stack_layouts →
独立栈布局金标准断言 (canary 槽位 / 帧大小 / 数据槽) — 与 EXP 无关,
纯粹来自二进制, 可作为后续栈课程的行为金标准断言集。

Deterministic-First: 断言全部来自真实 objdump 输出; 缺 WSL/objdump 时
诚实报告 SKIPPED。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "heap-corpus" / "corpus"
REVIEW = ROOT / "heap-corpus" / "review_queue"
OUT = ROOT / "autocorrect" / "stack_gold_assertions.json"


def _wsl_windows_path(p: Path) -> str:
    resolved = str(p.resolve())
    drive = resolved[0].lower()
    rest = resolved[2:].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def objdump_layout(binary: Path) -> dict | None:
    try:
        result = subprocess.run(
            ["wsl", "-e", "bash", "-c",
             "objdump -d --no-show-raw-insn "
             + "'" + _wsl_windows_path(binary) + "'"],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"error": str(error)}
    if result.returncode != 0:
        return {"error": result.stderr[:200]}
    sys.path.insert(0, str(ROOT / "pwn宝"))
    from pwnbao.core.x86_trace import trace_stack_layouts
    return {"functions": trace_stack_layouts(result.stdout)}


def main() -> None:
    sys.path.insert(0, str(ROOT / "autocorrect"))
    from case_manifest import inventory

    inv = inventory(CORPUS, REVIEW)
    stack_cases = [c for c in inv["cases"] if c["domain"] == "stack"]
    assertions = []
    for material in stack_cases:
        case_dir = Path(material["case_dir"])
        challenge = case_dir / "original" / "challenge"
        binary = next((p for p in challenge.iterdir()
                       if p.is_file() and not p.suffix), None)
        if binary is None:
            assertions.append({"case_id": material["case_id"],
                               "status": "SKIPPED", "reason": "no binary"})
            continue
        layout = objdump_layout(binary)
        if layout is None or "error" in (layout or {}):
            assertions.append({"case_id": material["case_id"],
                               "status": "SKIPPED",
                               "reason": (layout or {}).get("error", "")})
            continue
        canary_fns = [f["function"] for f in layout["functions"]
                      if any(s["kind"] == "canary" for s in f["slots"])]
        assertions.append({
            "case_id": material["case_id"],
            "status": "OK",
            "binary": str(binary.name),
            "functions": len(layout["functions"]),
            "canary_protected_functions": canary_fns,
            "frame_sizes": {f["function"]: f["frame_size"]
                            for f in layout["functions"]},
            "provenance": "OBSERVED (objdump)",
        })
    OUT.write_text(json.dumps(assertions, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    ok = sum(1 for a in assertions if a["status"] == "OK")
    print(f"stack gold assertions: {ok}/{len(assertions)} OK -> {OUT}")


if __name__ == "__main__":
    main()
