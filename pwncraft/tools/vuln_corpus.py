#!/usr/bin/env python3
"""Headless corpus runner for the vuln-point scanner.

`scan_vuln_points` expects a WslToolRunner, which shells out to `wsl.exe` and
therefore only exists on a Windows host.  When the tests run *inside* WSL we
already have objdump/readelf natively, so this wraps them in the same minimal
interface (`to_wsl_path` + `run_tool`) and reuses the real scanner unchanged.

Usage:
    python tools/vuln_corpus.py BINARY [BINARY ...] [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))


class ToolResult:
    def __init__(self, command, returncode, stdout, stderr):
        self.command, self.returncode = command, returncode
        self.stdout, self.stderr = stdout, stderr

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def combined_output(self) -> str:
        return "\n".join(p for p in (self.stdout.strip(), self.stderr.strip()) if p)


class NativeToolRunner:
    """Drop-in for WslToolRunner on a Linux host (we are already in WSL)."""

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def to_wsl_path(self, path: str | Path) -> str:
        return os.fspath(path).replace("\\", "/")

    def run_tool(self, tool: str, args: list[str], timeout: int | None = None) -> ToolResult:
        argv = [tool, *args]
        try:
            proc = subprocess.run(argv, capture_output=True,
                                  timeout=timeout or self.timeout)
        except FileNotFoundError:
            return ToolResult(argv, 127, "", f"{tool}: not found")
        except subprocess.TimeoutExpired:
            return ToolResult(argv, 124, "", f"{tool}: timeout")
        return ToolResult(argv, proc.returncode,
                          proc.stdout.decode("utf-8", "replace"),
                          proc.stderr.decode("utf-8", "replace"))


def scan(binary: Path, runner: NativeToolRunner) -> dict:
    from pwncraft.features.synth.vuln_points import scan_vuln_points
    return scan_vuln_points(binary, runner)


def _fmt(res: dict) -> str:
    lines = [
        f"  bits={res['bits']} functions={res['coverage']['functions']} "
        f"globals={res['coverage']['global_objects']} points={res['total']} "
        f"confirmed={res['confirmed']} risk={res['risk_total']}",
    ]
    for point in res["points"]:
        sev = str(point.get("severity"))
        if sev == "info":
            continue
        buf = point.get("buffer") or {}
        where = buf.get("symbol") or (f"rbp-{buf['offset']:#x}" if "offset" in buf
                                      else buf.get("kind", "-"))
        lines.append(
            f"    [{sev:8}] {point.get('verdict'):26} {point['callee']:12} "
            f"@ {point['vaddr']:>10}  {point.get('function','')[:26]:26} "
            f"len={point.get('length')} buf={where}")
        lines.append(f"               └ {str(point.get('reason'))[:150]}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binaries", nargs="*")
    parser.add_argument("--json", help="write the full scan result here")
    parser.add_argument("--corpus", help="ground-truth manifest to evaluate against")
    args = parser.parse_args()

    runner = NativeToolRunner()
    if args.corpus:
        result = evaluate(Path(args.corpus), runner)
        return 0 if result["missed"] == 0 and result["false_positives"] == 0 else 1
    report: dict[str, dict] = {}
    for raw in args.binaries:
        binary = Path(raw)
        print(f"\n=== {binary} ===")
        if not binary.exists():
            print("  MISSING")
            continue
        try:
            res = scan(binary, runner)
        except Exception as error:  # noqa: BLE001 - corpus tool
            print(f"  SCAN FAILED: {type(error).__name__}: {error}")
            continue
        report[str(binary)] = res
        print(_fmt(res))

    if args.json:
        Path(args.json).write_text(json.dumps(report, ensure_ascii=False, indent=1),
                                  encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0



def evaluate(manifest: Path, runner: "NativeToolRunner") -> dict:
    """对 ground-truth 语料跑扫描，统计命中 / 漏报 / 误报。"""
    spec = json.loads(manifest.read_text(encoding="utf-8"))
    results = []
    for case in spec.get("cases", []):
        binary = Path(case["binary"])
        entry = {"id": case["id"], "hit": [], "missed": [], "false_positive": [],
                 "skipped": None}
        if not binary.exists():
            entry["skipped"] = "binary 不存在"
            results.append(entry)
            continue
        try:
            report = scan(binary, runner)
        except Exception as error:                 # noqa: BLE001 - corpus tool
            entry["skipped"] = f"扫描失败: {type(error).__name__}: {error}"
            results.append(entry)
            continue
        found = {(str(p.get("verdict")), str(p.get("vaddr")).lower()): p
                 for p in report["points"]}
        for want in case.get("expected", []):
            key = (want["verdict"], want["vaddr"].lower())
            if key in found:
                point = found[key]
                if want.get("severity") and point.get("severity") != want["severity"]:
                    entry["missed"].append({**want, "got_severity": point.get("severity")})
                else:
                    entry["hit"].append(want)
            else:
                entry["missed"].append(want)
        for unwanted in case.get("not_expected", []):
            vaddr = str(unwanted.get("vaddr") or "").lower()
            for (verdict, address), point in found.items():
                if verdict != unwanted["verdict"]:
                    continue
                if vaddr and address != vaddr:
                    continue
                if not vaddr and unwanted.get("why", "").find("UAF") < 0:
                    continue
                entry["false_positive"].append({**unwanted, "got_severity": point.get("severity")})
        entry["functions_recovered"] = report["coverage"].get("functions_recovered", 0)
        results.append(entry)

    hits = sum(len(r["hit"]) for r in results)
    missed = sum(len(r["missed"]) for r in results)
    false_positives = sum(len(r["false_positive"]) for r in results)
    for item in results:
        state = "SKIP" if item["skipped"] else ("OK" if not item["missed"]
                                                and not item["false_positive"] else "FAIL")
        print(f"\n[{state}] {item['id']}"
              + (f"  (恢复函数 {item['functions_recovered']})"
                 if item.get("functions_recovered") else ""))
        if item["skipped"]:
            print(f"   skipped: {item['skipped']}")
            continue
        for hit in item["hit"]:
            print(f"   HIT  {hit['verdict']:26} {hit['vaddr']}")
        for miss in item["missed"]:
            extra = f" (实得 severity={miss['got_severity']})" if miss.get("got_severity") else ""
            print(f"   MISS {miss['verdict']:26} {miss['vaddr']}{extra}")
        for fp in item["false_positive"]:
            print(f"   FP   {fp['verdict']:26} {fp.get('vaddr', '-')}")
    total = hits + missed
    print(f"\n命中 {hits}/{total}  漏报 {missed}  误报 {false_positives}")
    return {"hits": hits, "missed": missed, "false_positives": false_positives,
            "cases": results}


if __name__ == "__main__":
    raise SystemExit(main())
