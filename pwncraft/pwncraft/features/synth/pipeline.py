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
    fmt_truth: Mapping[str, object] | None = None,
) -> dict:
    facts = collect_target_facts(binary, runner=runner)
    libc_symbols = collect_libc_symbols(libc, runner=runner) if libc else {}
    graph = build_primitive_graph(
        facts, patch_findings=patch_findings, stack_truth=stack_truth,
        gadgets=gadgets, heap_behavior=heap_behavior, libc_symbols=libc_symbols,
        fmt_truth=fmt_truth)
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
    menu: dict = {}
    menu_steps = None
    vuln_report: list = []
    gadgets: dict = {}
    static_stack_truth = None
    if stack_truth is None:
        from .menu import detect_menu, prelude_script
        from .vuln_points import scan_vuln_points
        try:
            result_objd = runner.run_tool("objdump", ["-d", "--",
                                                      runner.to_wsl_path(binary)])
            if result_objd.ok:
                from pwncraft.core.code_analysis import parse_disassembly
                fns = parse_disassembly(result_objd.stdout, max_functions=200000,
                                        max_lines=200000)["functions"]
                menu = detect_menu(binary, fns)
                menu_steps = prelude_script(menu) or None
                # 静态漏洞点确认：read/fgets 长度 vs 栈缓冲 → ret 偏移 = 槽+8
                vuln_report = scan_vuln_points(binary, runner, functions=fns)["points"]
                for point in vuln_report:
                    if (point.get("verdict") in ("overflow_confirmed", "unbounded_input")
                            and point.get("buffer", {}).get("kind") == "stack"):
                        slot = point["buffer"]["offset"]
                        static_stack_truth = {
                            "offset": hex(slot + 8),
                            "method": "static_vuln_point",
                            "evidence": [point.get("reason") or "",
                                         point.get("length_evidence") or ""],
                        }
                        break
        except Exception:
            vuln_report = vuln_report or []
        # ROPgadget 证明 pop rdi/rsi/rdx/rax（graph 的 gadget:* 门禁）
        try:
            from pwncraft.core.gadgets import parse_ropgadget_output
            gres = runner.run_tool("ropgadget", [
                "--binary", runner.to_wsl_path(binary),
                "--only", "pop|ret|syscall", "--depth", "10"], timeout=120)
            for gadget in parse_ropgadget_output(gres.stdout or gres.stderr,
                                                 source="verify", bits=64):
                ins = " ; ".join(item.lower().replace(" ", "")
                                 for item in gadget.instructions)
                if not ins.endswith("ret"):
                    continue
                for role, pat in (("rdi", "poprdi"), ("rsi", "poprsi"),
                                  ("rdx", "poprdx"), ("rax", "poprax")):
                    if pat in ins and role not in gadgets:
                        gadgets[role] = hex(gadget.address)
        except Exception:
            pass
    if stack_truth is None:
        if static_stack_truth is not None:
            # 静态漏洞点优先：不依赖 gdb/程序崩溃，菜单题直接可用
            stack_truth = static_stack_truth
            runtime = {"offset": int(static_stack_truth["offset"], 16),
                       "method": "static_vuln_point", "confidence": "conditional",
                       "evidence": static_stack_truth["evidence"],
                       "notes": ["偏移来自静态漏洞点证明（缓冲槽+8），未经运行时复核"]}
        else:
            facts = BinaryInspector().inspect(binary)
            try:
                runtime = discover_stack_offset(binary, runner=runner, bits=facts.bits,
                                                timeout=timeout, menu_steps=menu_steps)
            except Exception as error:
                runtime = {"offset": None, "method": "none", "confidence": "none",
                           "evidence": [], "notes": [f"gdb 不可用: {str(error)[:80]}"]}
            if runtime.get("offset") is not None and runtime.get("confidence") == "proven":
                stack_truth = {"offset": hex(int(runtime["offset"])),
                               "method": runtime["method"],
                               "evidence": runtime["evidence"]}
    # fmt 探针实验：存在格式串审计项时真跑目标验证可控性（修复③）
    fmt_truth = dict(analysis_options.pop("fmt_truth") or {})         if "fmt_truth" in analysis_options else {}
    review_items = list(analysis_options.get("patch_findings") or ())
    if not fmt_truth and any(str(item.get("category") or "") == "format_review"
                             for item in review_items):
        try:
            from .runtime import probe_fmt_control
            fmt_truth = probe_fmt_control(binary, runner=runner,
                                          menu_steps=menu_steps)
        except Exception as error:
            fmt_truth = {"controlled": False, "reason": f"探针失败: {error}"}
    # 先拿到运行时证据再建图：偏移必须进入 graph/strategy，否则策略仍是 blocked
    if gadgets:
        analysis_options.setdefault("gadgets", gadgets)
    analysis = analyze_target(binary, stack_truth=stack_truth, fmt_truth=fmt_truth or None,
                              **analysis_options)
    if not analysis.get("strategies"):
        # 没有任何候选策略（如纯沙箱/纯堆行为题）：诚实报告，不抛错
        runtime.setdefault("notes", []).append("无候选策略：缺少可证明的原语")
        return {"facts": analysis["facts"], "graph": analysis["graph"],
                "strategies": [], "best": None, "rendered": None,
                "runtime": runtime, "execution": None, "menu": menu,
                "verdict": {"verdict": "NO_STRATEGY", "error_count": 0,
                            "diagnostic_count": 0, "diagnostics": [],
                            "note": "无候选策略：缺少可证明原语，未生成 EXP"},
                "verification": {"status": "NOT_RUN",
                                 "summary": "无候选策略（缺可证明原语），未生成 EXP"}}
    generated = generate_exp(binary, strategy=strategy, runner=runner, analysis=analysis,
                             stack_truth=stack_truth, allow_missing=allow_missing,
                             **analysis_options)
    chosen: ExploitStrategy | None = generated.get("strategy")  # type: ignore[assignment]
    execution = None
    if (generated.get("rendered") is not None and chosen is not None
            and chosen.status == "ready" and not generated["rendered"].unresolved
            and generated["verdict"].get("verdict") == "ROUND_TRIP_CLEAN"):
        execution = run_exp_source(generated["rendered"].source, runner=runner,
                                   target_path=binary, marker=marker, timeout=timeout)
    verification = summarize_runtime(runtime, execution)
    if chosen is not None and chosen.status != "ready" and execution is None:
        verification = {**verification,
                        "summary": f"策略 {chosen.id} 非 ready，未执行 EXP；缺口："
                                   f"{'；'.join(chosen.missing) or '无'}"}
    return {**generated, "runtime": runtime, "execution": execution,
            "verification": verification, "menu": menu,
            "vuln_points": vuln_report}


def verify_all_exploits(
    binary: str | Path,
    *,
    runner,
    timeout: int = 60,
    marker: str = "PWN_SYNTH_OK",
    patch_findings: Sequence[Mapping[str, object]] = (),
    **analysis_options,
) -> dict:
    """生成并逐一实跑所有 ready 策略，成功者自动晋级。

    每个候选都独立执行，只有运行结果明确命中 marker 才算 VERIFIED；
    调用方可据此安全替换当前 EXP，失败候选不会被误标为可用。
    """
    options = dict(analysis_options)
    initial = analyze_target(binary, runner=runner, patch_findings=patch_findings,
                             **options)
    stack_candidates = {"ret2win", "ret2plt", "ret2libc", "srop", "orw"}
    needs_stack = any(item.id in stack_candidates for item in initial["strategies"])
    if options.get("stack_truth") is None and needs_stack:
        from pwncraft.core.workbench import BinaryInspector
        from .menu import detect_menu, prelude_script
        from .runtime import discover_stack_offset

        menu_steps = None
        try:
            result_objd = runner.run_tool("objdump", ["-d", "--", runner.to_wsl_path(binary)])
            if result_objd.ok:
                from pwncraft.core.code_analysis import parse_disassembly
                fns = parse_disassembly(result_objd.stdout, max_functions=200000)["functions"]
                menu_steps = prelude_script(detect_menu(binary, fns)) or None
        except Exception:
            pass
        facts = BinaryInspector().inspect(binary)
        observed = discover_stack_offset(binary, runner=runner, bits=facts.bits,
                                         timeout=timeout, menu_steps=menu_steps)
        if observed.get("offset") is not None and observed.get("confidence") == "proven":
            options["stack_truth"] = {
                "offset": hex(int(observed["offset"])),
                "method": observed.get("method", "observed"),
                "evidence": list(observed.get("evidence") or []),
            }
    analysis = (analyze_target(binary, runner=runner, patch_findings=patch_findings,
                               **options) if options != analysis_options else initial)
    results: list[dict] = []
    # 只对 ready 路线启动目标。blocked/unknown 仍然出现在报告里，便于
    # UI 展示缺口，但不会为每个占位候选重复执行一次 gdb/菜单探测。
    ready = [item for item in analysis.get("strategies", ())
             if item.status == "ready"]
    runtime_truth = options.get("stack_truth")
    for item in analysis.get("strategies", ()):
        if item.status != "ready":
            results.append({
                "strategy": item.id,
                "status": "NOT_RUN",
                "summary": f"策略 {item.id} 未执行：{'；'.join(item.missing) or '状态非 ready'}",
                "verified": False,
                "source": "",
                "skipped": True,
                "report": detection_report(analysis),
            })
            continue
        candidate_options = dict(options)
        if runtime_truth is not None:
            candidate_options["stack_truth"] = runtime_truth
        result = verify_exploit(binary, runner=runner, strategy=item.id,
                                timeout=timeout, marker=marker,
                                patch_findings=patch_findings, **candidate_options)
        verification = dict(result.get("verification") or {})
        results.append({
            "strategy": item.id,
            "status": verification.get("status", "NOT_RUN"),
            "summary": verification.get("summary", ""),
            "verified": verification.get("status") == "VERIFIED_SHELL",
            "source": (result.get("rendered").source
                        if result.get("rendered") is not None else ""),
            "skipped": False,
            "report": detection_report(result),
        })
    winner = next((item for item in results if item["verified"]), None)
    return {"analysis": detection_report(analysis), "candidates": results,
            "winner": winner, "verified_count": sum(1 for item in results if item["verified"]),
            "attempted_count": len(ready),
            "skipped_count": len(results) - len(ready)}


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
