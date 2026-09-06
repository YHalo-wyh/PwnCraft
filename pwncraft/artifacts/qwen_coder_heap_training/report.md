# Qwen3-Coder × pwncraft Heap 语义闭环实测

## 接入状态

- LM Studio 模型：`qwen3-coder-30b-a3b-instruct`
- GGUF：`Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf`（18,632,186,176 bytes）
- 本机预设：4096 context / 3584 input / 512 output / temperature 0.1 / timeout 180s
- LM Studio：parallel 1 / GPU offload 30% / Flash Attention / no mmproj
- pwncraft调用：手动模式；连接或编辑 EXP 不自动推理

## 完整 EXP 结果

| EXP | 耗时 | 预算策略 |
|---|---:|---|
| traditional/exp.py | 31.563s | 完整 IR |
| traditional/solve.py | 45.843s | 完整 IR |
| traditional/solve_alt.py | 50.985s | 精简重复 IR，完整 EXP 未截断 |
| Studentmanagement/题目附件/exp.py | 48.000s | 完整 IR |
| Studentmanagement/题目附件/solve_local.py | 47.844s | 完整 IR |

所有结果中的模型 ID 均为 `qwen3-coder-30b-a3b-instruct`。最长 EXP 使用 3579 / 3584 input tokens，仍在 LM Studio 的 4K context 内。

## 人工复核与反哺

- 接受/修改的高置信 helper：`copy_chunk(src,dst,length)`、`edit_bio(size,data)`、`reg(Id,name,passwd)`、`edit(size,payload)`。
- traditional 题目内的 dispatcher 规则：`cmd(1/2/3/4/7, ...)` 分别为 alloc/edit/show/free/copy，并通过 `argument_equals + arg_offset` 精确匹配。
- 拒绝并保存为负反馈：把 `args.GDB` 当成已选择分支、把 `size` 当作 `index`、缺少来源锚点和非法角色的建议。
- 静态分析已吸收：菜单 dispatcher、当前登录句柄、debug-only 分支、循环值折叠、recv-only helper、属性赋值泄漏链。
- strict replay：44 operations / 45 snapshots / 20 final logical chunks / no abort / no final warnings。

这里的“训练”是可审计的规则库、正负反馈与 JSONL 数据闭环，不在 pwncraft内直接修改模型权重。
