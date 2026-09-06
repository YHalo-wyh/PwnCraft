from __future__ import annotations
import json, sys, time
from dataclasses import asdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from pwnbao.features.ai import AIAnalysisRequest, AIProviderConfig, OpenAICompatibleProvider
from pwnbao.features.heapviz import analyze_heap_source
from run_eval import static_payload

JOBS=[
 ("cmd_alloc_free", Path(r"C:\Users\WYH\Desktop\软安决赛\traditional\exp.py"),
  "只审计 cmd(choice,*values) dispatcher。源码菜单语义已由题目注释和调用序列确认：choice=1 是 alloc(size,index)，choice=4 是 free(index)。分别返回两个 rule_candidate。matcher.argument_equals 用零基位置 0，output.arg_offset=1。不要返回 branch_choice。"),
 ("cmd_edit_show", Path(r"C:\Users\WYH\Desktop\软安决赛\traditional\exp.py"),
  "只审计 cmd(choice,*values) dispatcher。源码已确认 choice=2 是 edit(index,data)，choice=3 是 show(index)。分别返回两个 rule_candidate。matcher.argument_equals 用零基位置 0，output.arg_offset=1。不要返回 branch_choice。"),
 ("cmd_copy", Path(r"C:\Users\WYH\Desktop\软安决赛\traditional\exp.py"),
  "只审计 cmd(choice,*values) dispatcher。源码已确认 choice=7 是 copy(src,dst,length)。返回一个 rule_candidate；matcher.argument_equals 的位置0等于7，output.arg_offset=1，roles 为 src,dst,length。不要返回 branch_choice。"),
 ("student_helpers", Path(r"C:\Users\WYH\Desktop\软安决赛\Studentmanagement\题目附件\solve_local.py"),
  "复核当前静态 IR：reg(sid,name,password) 应为 alloc，index=sid、data=name、size unknown；login(sid) 选择当前句柄；edit_bio(size,data) 编辑当前登录句柄；show() 展示当前登录句柄；leak_bio_qword() 只解析 recv，不应额外产生 show。只在 IR 仍错误时返回校正，否则 proposals 为空。不要选择 args.GDB/CHECK 分支。"),
]

def main():
 out=Path(__file__).resolve().parent/'targeted';out.mkdir(exist_ok=True)
 cfg=AIProviderConfig(model='qwen3-coder-30b-a3b-instruct',timeout=180,max_tokens=512,context_budget_tokens=4096,max_input_tokens=3584,json_prefill=True)
 provider=OpenAICompatibleProvider(cfg)
 for gen,(name,path,instruction) in enumerate(JOBS[:3],200):
  src=path.read_text('utf8',errors='replace'); static=analyze_heap_source(src)
  req=AIAnalysisRequest.build(gen,src,{'family':'glibc','version':'2.35','arch':'amd64','safe_linking':True},static_payload(static),instruction=instruction)
  started=time.monotonic()
  try: payload={'job':name,'file':str(path),'result':provider.analyze(req).to_dict(),'elapsed_s':round(time.monotonic()-started,3)}
  except Exception as e: payload={'job':name,'file':str(path),'error':f'{type(e).__name__}: {e}','elapsed_s':round(time.monotonic()-started,3)}
  (out/f'{name}.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf8')
  print(json.dumps({'job':name,'error':payload.get('error',''),'elapsed_s':payload['elapsed_s']},ensure_ascii=False),flush=True)
  time.sleep(1)
if __name__=='__main__':main()
