from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pwncraft.features.ai import AIAnalysisRequest, AIProviderConfig, OpenAICompatibleProvider, PromptBudget
from pwncraft.features.heapviz import analyze_heap_source

CORPUS = [
    Path(r"C:\Users\WYH\Desktop\软安决赛\traditional\exp.py"),
    Path(r"C:\Users\WYH\Desktop\软安决赛\traditional\solve.py"),
    Path(r"C:\Users\WYH\Desktop\软安决赛\traditional\solve_alt.py"),
    Path(r"C:\Users\WYH\Desktop\软安决赛\Studentmanagement\题目附件\exp.py"),
    Path(r"C:\Users\WYH\Desktop\软安决赛\Studentmanagement\题目附件\solve_local.py"),
]


def static_payload(result):
    return {
        "valid": result.valid,
        "operations": [item.to_dict() for item in result.operations],
        "bindings": [
            {
                "source_id": item.source_id,
                "start": item.start,
                "end": item.end,
                "line": item.line,
                "end_line": item.end_line,
                "fingerprint": item.fingerprint,
                "loop_env": list(item.loop_env),
                "confidence": item.confidence,
                "match_status": item.match_status,
            }
            for item in result.bindings
        ],
        "branches": [asdict(item) for item in result.branch_groups],
        "diagnostics": [asdict(item) for item in result.diagnostics],
        "symbols": result.symbols,
    }


def main():
    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    config = AIProviderConfig(
        base_url="http://127.0.0.1:1234/v1",
        model="qwen3-coder-30b-a3b-instruct",
        timeout=180,
        temperature=0.1,
        max_tokens=512,
        context_budget_tokens=4096,
        max_input_tokens=3584,
        analysis_mode="manual",
        json_prefill=True,
    )
    provider = OpenAICompatibleProvider(config)
    print(provider.health_check(), flush=True)
    summary = []
    for generation, path in enumerate(CORPUS, 1):
        source = path.read_text(encoding="utf-8", errors="replace")
        static = analyze_heap_source(source)
        request = AIAnalysisRequest.build(
            generation,
            source,
            {"family": "glibc", "version": "2.35", "arch": "amd64", "bits": 64, "safe_linking": True},
            static_payload(static),
            instruction=(
                "审计静态 Heap IR 与完整 EXP。只提出能由源码证明、能改善堆示意图的高价值校正；"
                "优先指出 helper 语义/参数角色错误、菜单 dispatcher、show/recv 泄漏链、"
                "动态调试分支之后不应丢失的共同后缀。不要猜测运行时地址或 NULL。"
            ),
        )
        messages, budget, compact_static = provider.prepare_messages(request, config)
        started = time.monotonic()
        try:
            result = provider.analyze(request)
            payload = {
                "file": str(path),
                "static_operation_count": len(static.operations),
                "static_diagnostics": [asdict(item) for item in static.diagnostics],
                "prompt_budget": asdict(budget),
                "compact_static_ir": compact_static,
                "result": result.to_dict(),
            }
            error = ""
        except Exception as exc:
            payload = {
                "file": str(path),
                "static_operation_count": len(static.operations),
                "static_diagnostics": [asdict(item) for item in static.diagnostics],
                "prompt_budget": asdict(budget),
                "compact_static_ir": compact_static,
                "error": f"{type(exc).__name__}: {exc}",
            }
            error = payload["error"]
        slug = f"{generation:02d}_{path.parent.name}_{path.stem}".replace(" ", "_")
        target = out_dir / f"{slug}.json"
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        summary.append({"file": str(path), "artifact": str(target), "error": error, "elapsed_s": round(time.monotonic() - started, 3)})
        print(json.dumps(summary[-1], ensure_ascii=False), flush=True)
    (out_dir.parent / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
