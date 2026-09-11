#!/usr/bin/env python3
"""Offline synthesis entry: detect → primitive graph → strategy → EXP → review_queue.

单题：
    python tools/synth_case.py <binary> [--libc libc.so.6] [--strategy ret2win]
        [--offset 0x48] [--gadget rdi=0x401234] [--deposit DIR] [--json]

喂题（批量，读取 heap-corpus 的 corpus/<case_id>/original/challenge*）：
    python tools/synth_case.py --corpus ../heap-corpus/corpus \
        --deposit ../heap-corpus/review_queue/synth [--limit 20]

全部离线、不执行目标二进制；生成物默认 trainable=false，先落评审区。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from pwncraft.features.synth import deposit_case, generate_exp
from pwncraft.features.synth.pipeline import detection_report


def default_runner():
    """Windows 宿主用 wsl.exe 跑 objdump；WSL/Linux 宿主直接跑本地工具。"""
    if os.name == "nt":
        from pwncraft.core.wsl import WslToolRunner

        return WslToolRunner()
    from pwncraft.features.synth.facts import LocalToolRunner

    return LocalToolRunner()


def parse_gadgets(pairs: list[str] | None) -> dict[str, str]:
    gadgets: dict[str, str] = {}
    for item in pairs or []:
        name, separator, value = str(item).partition("=")
        if not separator or not name.strip() or not value.strip():
            raise ValueError(f"--gadget 需要 name=value 形式: {item!r}")
        gadgets[name.strip()] = value.strip()
    return gadgets


def run_one(binary: Path, *, runner, strategy: str = "", libc: str | None = None,
            stack_truth: dict | None = None, gadgets: dict | None = None,
            dest: str | None = None) -> tuple[dict, dict]:
    generated = generate_exp(binary, strategy=strategy, runner=runner, libc=libc,
                             stack_truth=stack_truth, gadgets=gadgets, allow_missing=True)
    report = detection_report(generated)
    rendered = generated.get("rendered")
    outcome = {
        "target": report["target"],
        "best": report["best"],
        "verdict": generated["verdict"]["verdict"],
        "unresolved": list(rendered.unresolved) if rendered is not None else [],
    }
    if dest:
        outcome["deposit"] = deposit_case(dest, generated)
    return outcome, generated


def corpus_cases(corpus: Path):
    """corpus/<case_id>/original/challenge/* → (case_id, binary, libc)。

    challenge 目录里可能同时放题目 ELF 与 libc；.so 归为 libc，其余取第一个 ELF。
    """
    for manifest in sorted(corpus.glob("*/manifest.json")):
        case_dir = manifest.parent
        binary: Path | None = None
        libc: Path | None = None
        for candidate in sorted((case_dir / "original" / "challenge").glob("*")):
            if not candidate.is_file():
                continue
            try:
                if candidate.read_bytes()[:4] != b"\x7fELF":
                    continue
            except OSError:
                continue
            if ".so" in candidate.name.lower():
                libc = libc or candidate
            else:
                binary = binary or candidate
        if binary is not None:
            yield case_dir.name, binary, libc


def _print_single(outcome: dict, source: str) -> None:
    best = outcome.get("best") or {}
    print(f"[target] {outcome['target']['path']}  sha256={outcome['target']['sha256'][:16]}…")
    print(f"[best]   {best.get('id') or '(无候选策略)'}  status={best.get('status') or '-'}")
    for item in best.get("missing") or []:
        print(f"  gap: {item}")
    print(f"[verdict] {outcome['verdict']}  unresolved={len(outcome['unresolved'])}")
    if outcome.get("deposit"):
        print(f"[deposit] {outcome['deposit']['dir']}")
    print("-" * 72)
    if source:
        print(source)
    else:
        print("（静态事实不足，未产生 EXP 骨架；检测结果已沉淀到评审区）")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PwnCraft exploit synthesis (offline)")
    parser.add_argument("binary", nargs="?", help="单个目标 ELF")
    parser.add_argument("--corpus", help="批量：corpus 根目录（含 <case_id>/manifest.json）")
    parser.add_argument("--deposit", help="review_queue 输出目录")
    parser.add_argument("--strategy", default="", help="指定策略 id（默认选最优）")
    parser.add_argument("--libc", help="libc 文件（提供后 ret2libc 可解析偏移）")
    parser.add_argument("--offset", help="已观测的返回地址偏移（如 0x48）")
    parser.add_argument("--gadget", action="append", default=[],
                        help="gadget shelf 事实，可重复：rdi=0x401234 rax=0x401005")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--json", action="store_true", help="单题输出 JSON（含源码）")
    args = parser.parse_args(argv)

    runner = default_runner()
    stack_truth = {"offset": args.offset} if args.offset else None
    gadgets = parse_gadgets(args.gadget)

    if args.binary:
        outcome, generated = run_one(Path(args.binary), runner=runner, strategy=args.strategy,
                                     libc=args.libc, stack_truth=stack_truth, gadgets=gadgets,
                                     dest=args.deposit)
        source = generated["rendered"].source if generated.get("rendered") is not None else ""
        if args.json:
            print(json.dumps({**outcome, "source": source, "graph": generated["graph"].to_dict()},
                             ensure_ascii=False, indent=2))
        else:
            _print_single(outcome, source)
        return 0

    if not args.corpus:
        parser.error("需要 <binary> 或 --corpus DIR")
    corpus = Path(args.corpus)
    if not corpus.is_dir():
        parser.error(f"corpus 目录不存在: {corpus}")
    records: list[dict] = []
    processed = 0
    for case_id, binary, case_libc in corpus_cases(corpus):
        if args.limit and processed >= args.limit:
            break
        processed += 1
        try:
            outcome, _ = run_one(binary, runner=runner, strategy=args.strategy,
                                 libc=args.libc or (str(case_libc) if case_libc else None),
                                 stack_truth=stack_truth, gadgets=gadgets,
                                 dest=args.deposit)
            best = outcome.get("best") or {}
            record = {"case_id": case_id, "ok": True, "strategy": best.get("id"),
                      "status": best.get("status"), "verdict": outcome["verdict"],
                      "unresolved": len(outcome["unresolved"]),
                      "deposit": (outcome.get("deposit") or {}).get("case_id")}
        except Exception as error:  # 单题失败不阻断批量
            record = {"case_id": case_id, "ok": False, "error": str(error)}
        records.append(record)
        print(f"{'OK ' if record['ok'] else 'ERR'} {case_id}: "
              f"{record.get('strategy') or ''} {record.get('status') or ''} "
              f"{record.get('verdict') or ''} {record.get('error') or ''}".rstrip())

    summary = {"total": len(records),
               "ok": sum(1 for item in records if item["ok"]),
               "ready": sum(1 for item in records if item.get("status") == "ready"),
               "records": records}
    if args.deposit:
        Path(args.deposit).mkdir(parents=True, exist_ok=True)
        (Path(args.deposit) / "synth_batch_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: summary[key] for key in ("total", "ok", "ready")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
