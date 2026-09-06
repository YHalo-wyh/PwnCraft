from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwnbao.features.ai import AIAnalysisRequest, AIProviderConfig, PromptBudget
from pwnbao.features.ai.provider import OpenAICompatibleProvider
from pwnbao.features.heapviz import analyze_heap_source

SOURCE_PATH = Path(r"C:/Users/WYH/Desktop/软安决赛/traditional/solve.py")
OUT = Path("artifacts/lmstudio_solve_eval")


def static_payload(result):
    symbols = {}
    for key, value in list(sorted(result.symbols.items()))[:128]:
        if isinstance(value, (str, bytes)) and len(value) > 240:
            symbols[str(key)] = str(value)[:240] + "..."
        elif isinstance(value, (list, tuple, dict, set)):
            rendered = repr(value)
            symbols[str(key)] = rendered[:240] + ("..." if len(rendered) > 240 else "")
        elif isinstance(value, (int, float, bool)) or value is None:
            symbols[str(key)] = value
        else:
            symbols[str(key)] = repr(value)[:240]
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
        "branches": [],
        "diagnostics": [
            {
                "severity": item.severity,
                "code": item.code,
                "message": item.message,
                "start": item.start,
                "end": item.end,
                "line": item.line,
                "suggestion": item.suggestion,
            }
            for item in result.diagnostics
        ],
        "symbols": symbols,
        "last_valid_operations": [],
    }


def main():
    source = SOURCE_PATH.read_text(encoding="utf-8")
    analysis = analyze_heap_source(source)
    config = AIProviderConfig(
        base_url="http://127.0.0.1:1234/v1",
        model="qwen3.6-27b",
        timeout=300.0,
        temperature=0.1,
        max_tokens=768,
        analysis_mode="manual",
        context_budget_tokens=4096,
        max_input_tokens=3200,
    )
    request = AIAnalysisRequest.build(
        1,
        source,
        {
            "family": "glibc",
            "version": "2.35",
            "arch": "amd64",
            "bits": 64,
            "alignment": 16,
            "tcache_enabled": True,
            "safe_linking": True,
            "heap_base": "heap_base",
        },
        static_payload(analysis),
        instruction=(
            "这是第二轮格式反馈测试。仅校验并返回最有价值的 helper_mapping，"
            "优先 add(size,idx) 和 copy(src,dst,len)。payload_json 里直接放 semantic/function/roles/"
            "arity/keywords/parameter_names，不要再包 mapping、operation 或 source_range。"
            "必须从 helper 定义的 send 顺序核实参数角色，不编造运行时地址。"
        ),
    )
    provider = OpenAICompatibleProvider(config)
    health = provider.health_check()
    models = provider.list_models()
    messages = provider._messages(request)
    budget = PromptBudget.estimate(json.dumps(messages, ensure_ascii=False, separators=(",", ":")), config)
    summary = {
        "source_path": str(SOURCE_PATH),
        "source_hash": request.source_hash,
        "source_lines": len(source.splitlines()),
        "source_bytes": len(source.encode("utf-8")),
        "static_valid": analysis.valid,
        "static_operation_count": len(analysis.operations),
        "static_diagnostic_count": len(analysis.diagnostics),
        "health": health,
        "models": list(models),
        "config": config.public_dict(),
        "prompt_budget": budget.__dict__,
    }
    (OUT / "request_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "static_operations.json").write_text(
        json.dumps({"operations": [item.to_dict() for item in analysis.operations], "diagnostics": [item.__dict__ for item in analysis.diagnostics]}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    if not budget.fits:
        raise SystemExit("prompt over budget")
    started = time.perf_counter()
    try:
        result = provider.analyze(request)
    except Exception as error:
        failure = {"error": str(error), "elapsed_seconds": round(time.perf_counter() - started, 3)}
        (OUT / "ai_failure.json").write_text(json.dumps(failure, ensure_ascii=False, indent=2), encoding="utf-8")
        raise
    elapsed = time.perf_counter() - started
    payload = result.to_dict()
    payload["wall_elapsed_seconds"] = round(elapsed, 3)
    (OUT / "ai_result.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
