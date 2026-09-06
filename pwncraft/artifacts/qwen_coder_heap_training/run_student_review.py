from __future__ import annotations
import json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from pwncraft.features.ai import AIAnalysisRequest,AIProviderConfig,OpenAICompatibleProvider,PromptBudget
from pwncraft.features.heapviz import analyze_heap_source
from run_eval import static_payload
p=Path(r'C:\Users\WYH\Desktop\软安决赛\Studentmanagement\题目附件\exp.py')
s=p.read_text('utf8',errors='replace'); r=analyze_heap_source(s)
req=AIAnalysisRequest.build(500,s,{'family':'glibc','version':'2.35','arch':'amd64','safe_linking':True},static_payload(r),instruction='复核堆 IR：reg(Id,name,passwd) 应为 alloc(index=Id,data=name,size unknown)；login 选择当前句柄；edit(size,payload) 编辑当前句柄且 size 不是 index；show() 展示当前句柄；recv 派生 heap/libc。只返回仍存在的错误，不猜地址或 NULL。')
cfg=AIProviderConfig(model='qwen3-coder-30b-a3b-instruct',timeout=180,max_tokens=512,context_budget_tokens=4096,max_input_tokens=3584,json_prefill=True)
provider=OpenAICompatibleProvider(cfg)
msgs=provider._messages(req,True); budget=PromptBudget.estimate(json.dumps(msgs,ensure_ascii=False,separators=(',',':')),cfg)
started=time.monotonic()
try: out={'budget':budget.__dict__,'static_ops':len(r.operations),'result':provider.analyze(req).to_dict(),'elapsed_s':round(time.monotonic()-started,3)}
except Exception as e:out={'budget':budget.__dict__,'static_ops':len(r.operations),'error':f'{type(e).__name__}: {e}'}
Path(__file__).with_name('targeted').mkdir(exist_ok=True)
Path(__file__).with_name('targeted').joinpath('student_review.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
print(json.dumps({'error':out.get('error'),'elapsed':out.get('elapsed_s'),'budget':budget.diagnostic},ensure_ascii=False))
