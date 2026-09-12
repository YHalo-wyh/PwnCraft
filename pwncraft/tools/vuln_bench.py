#!/usr/bin/env python3
"""Measure the vuln scanner's recall against a labeled corpus.

The corpus (see tools/vuln_index.py) labels every binary by the vulnerability
class of its source directory.  "Recall" here means: **did the scanner produce
at least one finding whose category matches the expected class?**  That is the
metric that matters for "drop a file in and get the pwn vuln out" — a scanner
that stays silent is useless even if it is never wrong.

Usage:
    python tools/vuln_bench.py datasets/vuln_corpus/pwn99.json
    python tools/vuln_bench.py --show-silent      # list binaries with no findings
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.vuln_corpus import NativeToolRunner, scan  # noqa: E402


def make_runner():
    """Use WSL tools on Windows so UTF-8 challenge paths remain valid."""
    if __import__("os").name == "nt":
        from pwncraft.core.wsl import WslToolRunner
        return WslToolRunner()
    return NativeToolRunner()


def resolve_binary_path(raw: str) -> Path:
    """Resolve manifests written in WSL on Windows hosts (and vice versa)."""
    value = str(raw)
    candidate = Path(value)
    if candidate.exists():
        return candidate
    match = __import__("re").match(r"^/mnt/([a-zA-Z])/(.*)$", value)
    if match:
        windows = Path(f"{match.group(1).upper()}:/{match.group(2)}")
        if windows.exists():
            return windows
    if value.startswith("/mnt/"):
        native = Path(value.replace("/", "\\"))
        if native.exists():
            return native
    return candidate


def run_case(case: dict, runner) -> dict:
    binary = resolve_binary_path(case["binary"])
    result = {"id": case["id"], "category": case["category"],
              "expected": set(case["expected_categories"]), "hit": False,
              "silent": False, "error": None, "severity": {}, "verdicts": [],
              "recovered": 0}
    if not binary.exists():
        result["error"] = "binary 缺失"
        return result
    try:
        report = scan(binary, runner)
    except Exception as error:                       # noqa: BLE001 - bench tool
        result["error"] = f"{type(error).__name__}: {str(error)[:90]}"
        return result
    result["recovered"] = report["coverage"].get("functions_recovered", 0)
    result["severity"] = report["severity"]
    # medium 是“证据不足但已定位到危险数据流”的真实 Pwn 线索，不能
    # 在召回率里当作静默；critical/high 仍可由 verdicts 区分优先级。
    risk = [p for p in report["points"] if p["severity"] in {"critical", "high", "medium"}]
    result["verdicts"] = sorted({str(p["verdict"]) for p in risk})
    result["silent"] = not risk
    result["hit"] = any(str(p.get("category")) in result["expected"] for p in risk)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--show-silent", action="store_true",
                        help="列出完全没有任何 critical/high 发现的目标")
    parser.add_argument("--json", help="把逐题结果写到该文件")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    cases = manifest.get("cases", [])
    if not cases:
        print("清单为空", file=sys.stderr)
        return 1

    runner = make_runner()
    per_category: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        outcome = run_case(case, runner)
        per_category[outcome["category"]].append(outcome)

    print(f"{'类别':16} {'用例':>4} {'命中':>4} {'静默':>4} {'报错':>4}  召回率")
    print("-" * 62)
    total = hits = silent = errors = 0
    for name in sorted(per_category):
        rows = per_category[name]
        ok = sum(1 for r in rows if r["hit"])
        quiet = sum(1 for r in rows if r["silent"] and not r["error"])
        bad = sum(1 for r in rows if r["error"])
        total += len(rows); hits += ok; silent += quiet; errors += bad
        print(f"{name:16} {len(rows):>4} {ok:>4} {quiet:>4} {bad:>4}  "
              f"{ok / len(rows):>6.1%}")

    print("-" * 62)
    print(f"{'合计':16} {total:>4} {hits:>4} {silent:>4} {errors:>4}  {hits / total:>6.1%}")

    misses = [(c, [r for r in rows if not r["hit"] and not r["error"]])
              for c, rows in sorted(per_category.items())]
    print("\n=== 漏报明细 ===")
    for category, rows in misses:
        for row in rows[:14]:
            mark = "SILENT" if row["silent"] else "MISCLASS"
            print(f"  [{mark:8}] {row['id']:44} 实得={','.join(row['verdicts'][:3]) or '-'}")
        if len(rows) > 14:
            print(f"  ... {category} 另有 {len(rows) - 14} 个")

    if args.show_silent:
        print("\n=== 完全静默（无 critical/high）===")
        for category, rows in sorted(per_category.items()):
            for row in rows:
                if row["silent"] and not row["error"]:
                    print(f"  {category:16} {row['id']}")

    if args.json:
        Path(args.json).write_text(
            json.dumps({c: r for c, r in per_category.items()},
                       ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n逐题结果写入 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
