"""Synthesis pipeline: detect → primitive graph → strategy → EXP → round-trip.

One deterministic pass; every stage records its evidence and its gaps.  The
pipeline never executes the target and never invents an address — runtime
verification stays a separate, explicit step.
"""
from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from .deposit import deposit_case as _deposit_case
from .facts import TargetFacts, collect_libc_symbols, collect_target_facts
from .graph import PrimitiveGraph, build_primitive_graph
from .render import RenderedExp, render_exp
from .roundtrip import verify_exp
from .strategy import ExploitStrategy, best_strategy, plan_strategies


def analyze_target(
    binary: str | Path,
    *,
    runner=None,
    patch_findings: Sequence[Mapping[str, object]] = (),
    stack_truth: Mapping[str, object] | None = None,
    gadgets: Mapping[str, object] | None = None,
    heap_behavior: Mapping[str, object] | None = None,
    libc: str | Path | None = None,
) -> dict:
    facts = collect_target_facts(binary, runner=runner)
    libc_symbols = collect_libc_symbols(libc, runner=runner) if libc else {}
    graph = build_primitive_graph(
        facts, patch_findings=patch_findings, stack_truth=stack_truth,
        gadgets=gadgets, heap_behavior=heap_behavior, libc_symbols=libc_symbols)
    strategies = plan_strategies(facts, graph, libc_symbols=libc_symbols)
    return {"facts": facts, "graph": graph, "strategies": strategies,
            "libc_symbols": libc_symbols, "best": best_strategy(strategies)}


def generate_exp(
    binary: str | Path,
    *,
    strategy: str = "",
    allow_missing: bool = False,
    **analysis_options,
) -> dict:
    analysis = analyze_target(binary, **analysis_options)
    strategies: list[ExploitStrategy] = analysis["strategies"]
    chosen = next((item for item in strategies if item.id == strategy), None) if strategy \
        else analysis["best"]
    if chosen is None:
        if not allow_missing:
            available = ", ".join(item.id for item in strategies) or "无"
            raise ValueError(f"没有匹配的策略 {strategy!r}（可选：{available}）")
        return {**analysis, "strategy": None, "rendered": None,
                "verdict": {"verdict": "NO_STRATEGY", "error_count": 0,
                            "diagnostic_count": 0, "diagnostics": [],
                            "note": "静态事实不足，未产生候选策略；检测结果仍可作为负样本沉淀"}}
    rendered: RenderedExp = render_exp(
        analysis["facts"], chosen, libc_symbols=analysis["libc_symbols"],
        stack_truth=analysis_options.get("stack_truth"),
        gadgets=analysis_options.get("gadgets"))
    verdict = verify_exp(rendered.source, bits=analysis["facts"].bits,
                         pie=analysis["facts"].is_pie())
    return {**analysis, "strategy": chosen, "rendered": rendered, "verdict": verdict}


def deposit_case(dest_root: str | Path, generated: Mapping[str, object]) -> dict:
    return _deposit_case(
        dest_root,
        facts=generated["facts"],                 # type: ignore[arg-type]
        graph=generated["graph"],                 # type: ignore[arg-type]
        strategies=generated["strategies"],       # type: ignore[arg-type]
        rendered=generated["rendered"],           # type: ignore[arg-type]
        verdict=generated["verdict"],             # type: ignore[arg-type]
    )


def detection_report(analysis: Mapping[str, object], *, include_facts: bool = False) -> dict:
    """JSON-safe 检测报告（RPC / CLI 共用）。"""
    facts: TargetFacts = analysis["facts"]        # type: ignore[assignment]
    graph: PrimitiveGraph = analysis["graph"]     # type: ignore[assignment]
    strategies: Sequence[ExploitStrategy] = analysis["strategies"]  # type: ignore[assignment]
    best: ExploitStrategy | None = analysis.get("best")             # type: ignore[assignment]
    report = {
        "target": {"path": facts.path, "sha256": facts.sha256,
                   "arch": facts.architecture, "bits": facts.bits,
                   "security": dict(facts.security)},
        "summary": {
            "plt": len(facts.plt), "got": len(facts.got),
            "functions": len(facts.functions), "win_functions": len(facts.win_functions),
            "leak_sites": len(facts.leak_sites), "syscalls": len(facts.syscalls),
            "strings": dict(facts.strings), "libc_symbols": len(analysis.get("libc_symbols") or {}),
            "notes": list(facts.notes),
        },
        "graph": graph.to_dict(),
        "strategies": [item.to_dict() for item in strategies],
        "best": best.to_dict() if best is not None else None,
    }
    if include_facts:
        report["facts"] = facts.to_dict()
    return report
