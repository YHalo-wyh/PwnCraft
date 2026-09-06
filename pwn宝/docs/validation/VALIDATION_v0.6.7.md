# pwn宝 v0.6.7 验证记录

## LM Studio

- 模型：`qwen3-coder-30b-a3b-instruct`
- 文件：`F:\LLM\lmstudio-community\Qwen3-Coder-30B-A3B-Instruct-GGUF\Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf`
- 大小：18,632,186,176 bytes
- 服务：`http://127.0.0.1:1234/v1`
- 加载：4096 context / parallel 1 / GPU offload 30% / TTL 3600
- 完整 EXP 请求实测：本轮 5 份题目分别耗时 31.563 / 45.843 / 50.985 / 48.000 / 47.844 秒，均使用精确 Coder 模型 ID。
- 最长 `solve_alt.py` 在 4K context 内使用预算精简：3579 / 3584 input tokens，仅去除重复 Heap IR 字段，完整 EXP 未截断。

## 本地 EXP 语料

1. `C:\Users\WYH\Desktop\软安决赛\traditional\exp.py`
2. `C:\Users\WYH\Desktop\软安决赛\traditional\solve.py`
3. `C:\Users\WYH\Desktop\软安决赛\traditional\solve_alt.py`
4. `C:\Users\WYH\Desktop\软安决赛\Studentmanagement\题目附件\exp.py`
5. `C:\Users\WYH\Desktop\软安决赛\Studentmanagement\题目附件\solve_local.py`

## 复核结果

- 新增 12 条 Qwen Coder 人工复核反馈，导出后反馈共 14 条。
- 全局精确规则：`copy_chunk(src,dst,length)`、`edit_bio(size,data)`、`reg(Id,name,passwd)`、`edit(size,payload)`。
- traditional 场景规则：`cmd(1/2/3/4/7, ...)` 分别映射 alloc/edit/show/free/copy。
- 拒绝了将 `args.GDB` 推测为已选分支、将 `size` 误映射为 index 等错误候选。
- traditional 校正重放：44 个语义操作、45 个快照、20 个最终逻辑 chunk，无 allocator abort，无最终 warning。
- `reg` 的真实 malloc size 未出现在 EXP 源码中，因此保持 `unknown`，不用 ID 伪造 size。

## 自动化回归

Windows Python 3.10：

```text
D:\python310\python.exe -m unittest discover -s tests -v
Ran 94 tests in 11.266s
OK
```

## 证据文件

- `artifacts/qwen_coder_heap_training/results/`：完整 EXP 模型返回。
- `artifacts/qwen_coder_heap_training/targeted/`：针对 helper/dispatcher 的模型校正。
- `artifacts/qwen_coder_heap_training/traditional.pwnbao-helper.json`：场景 helper 规则。
- `artifacts/qwen_coder_heap_training/traditional_corrected_replay.json`：严格重放快照。
- `artifacts/qwen_coder_heap_training/reviewed_feedback.jsonl`：审核后的正负反馈。
- `artifacts/qwen_coder_heap_training/learning_summary.json`：学习结果汇总。
