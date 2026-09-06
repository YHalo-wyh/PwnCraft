from __future__ import annotations
import json, sys, time
from dataclasses import asdict
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from pwncraft.features.ai import AIAnalysisRequest, AIProviderConfig, OpenAICompatibleProvider
from pwncraft.features.heapviz import analyze_heap_source
from run_eval import static_payload
path = Path(r"C:\Users\WYH\Desktop\软安决赛\traditional\solve_alt.py")
source = path.read_text('utf8', errors='replace')
static = analyze_heap_source(source)
config = AIProviderConfig(model='qwen3-coder-30b-a3b-instruct')
provider = OpenAICompatibleProvider(config)
request = AIAnalysisRequest.build(
    3, source,
    {'family':'glibc','version':'2.35','arch':'amd64','bits':64,'safe_linking':True},
    static_payload(static),
    instruction=(
        '审计静态 Heap IR 与完整 EXP。只提出能由源码证明、能改善堆示意图的高价值校正；'
        '优先指出 helper 语义/参数角色错误、菜单 dispatcher、show/recv 泄漏链、'
        '动态调试分支之后不应丢失的共同后缀。不要猜测运行时地址或 NULL。'
    ),
)
_messages, budget, compact_static = provider.prepare_messages(request, config)
started = time.monotonic()
result = provider.analyze(request)
payload = {
    'file': str(path),
    'static_operation_count': len(static.operations),
    'static_diagnostics': [asdict(item) for item in static.diagnostics],
    'prompt_budget': asdict(budget),
    'compact_static_ir': compact_static,
    'result': result.to_dict(),
}
target = Path(__file__).resolve().parent / 'results' / '03_traditional_solve_alt.json'
target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), 'utf8')
print(json.dumps({'file':str(path),'artifact':str(target),'error':'','elapsed_s':round(time.monotonic()-started,3),'compact_static_ir':compact_static,'budget':asdict(budget)}, ensure_ascii=False))
