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
    analysis: Mapping[str, object] | None = None,
    **analysis_options,
) -> dict:
    analysis = analysis or analyze_target(binary, **analysis_options)
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
        verification=generated.get("verification"),  # type: ignore[arg-type]
    )


def verify_exploit(
    binary: str | Path,
    *,
    runner,
    strategy: str = "",
    timeout: int = 60,
    marker: str = "PWN_SYNTH_OK",
    allow_missing: bool = False,
    stack_truth: Mapping[str, object] | None = None,
    **analysis_options,
) -> dict:
    """运行时闭环：检测 → gdb 测偏移 → 渲染 → 执行生成的 EXP → 带证据的结论。

    调用本函数即代表用户要求**真跑一次目标**（opt-in）；无法证明时如实记
    NOT_RUN / UNCONFIRMED，绝不把「进程起来了」当作「打通了」。
    """
    from pwncraft.core.workbench import BinaryInspector

    from .runtime import discover_stack_offset, run_exp_source, summarize_runtime

    runtime: dict = {"offset": None, "method": "none", "confidence": "none", "evidence": [],
                     "notes": ["已由调用方提供偏移事实，跳过 gdb 测量"]}
    if stack_truth is None:
        facts = BinaryInspector().inspect(binary)
        runtime = discover_stack_offset(binary, runner=runner, bits=facts.bits, timeout=timeout)
        if runtime.get("offset") is not None:
            stack_truth = {"offset": hex(int(runtime["offset"])), "method": runtime["method"],
                           "evidence": runtime["evidence"]}
    # 先拿到运行时证据再建图：偏移必须进入 graph/strategy，否则策略仍是 blocked
    analysis = analyze_target(binary, stack_truth=stack_truth, **analysis_options)
    generated = generate_exp(binary, strategy=strategy, runner=runner, analysis=analysis,
                             stack_truth=stack_truth, allow_missing=allow_missing,
                             **analysis_options)
    chosen: ExploitStrategy | None = generated.get("strategy")  # type: ignore[assignment]
    execution = None
    if generated.get("rendered") is not None and chosen is not None and chosen.status == "ready":
        execution = run_exp_source(generated["rendered"].source, runner=runner,
                                   target_path=binary, marker=marker, timeout=timeout)
    verification = summarize_runtime(runtime, execution)
    if chosen is not None and chosen.status != "ready" and execution is None:
        verification = {**verification,
                        "summary": f"策略 {chosen.id} 非 ready，未执行 EXP；缺口："
                                   f"{'；'.join(chosen.missing) or '无'}"}
    return {**generated, "runtime": runtime, "execution": execution,
            "verification": verification}


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
