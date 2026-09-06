# pwn宝 v0.6.7

## 本地 AI 模型

- 默认模型更正为 `Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf`，LM Studio 请求使用精确 ID `qwen3-coder-30b-a3b-instruct`。
- 本机预设收敛为 4096 context、3584 input、512 output、temperature 0.1、180 秒 timeout、parallel 1 和 GPU offload 30%。超预算时只精简重复 Heap IR，不截断 EXP。
- Prompt 针对 Coder 模型约束 helper 映射、dispatcher 字面量条件、`arg_offset` 和负样本，禁止把 `args.GDB` 存在误判为真实分支。

## 语义识别反哺

- 新增 dispatcher 规则：支持 `matcher.argument_equals` 匹配 `cmd(1, ...)` 一类菜单选择器，并用 `output.arg_offset` 跳过 choice 参数。
- 识别 `reg/register/signup`、`sid/uid` 等常见 helper 变体，同时对参数名与角色明显冲突的 AI 规则做严格拒绝。
- 追踪 login/select 类当前句柄，支持 `edit(size, data)` 和 `show()` 隐式操作当前 chunk。
- 静态展开循环环境表达式，例如 `100+i`；静态表达式 `0x80|14` 仍保留源码形式。
- recv-only helper 不再产生重复 SHOW；支持 `libc.address = u64(recv(...)) - offset` 属性赋值的 DERIVE_VALUE 数据流。
- `args.GDB` 等仅影响调试的未知分支不再截断后续堆事件，只生成 `heap_neutral_branch` 诊断。

## 校正与学习

- 使用 5 份本地真实 EXP 进行模型分析、人工复核和严格 allocator replay。
- 安全的精确 helper 签名保存为全局规则；`cmd(choice, ...)` 类题目特定语义仅保存在当前场景。
- 错误分支选择和错误参数角色保存为负反馈，避免后续重复建议。
- “训练”为规则库 + 正负反馈 + JSONL 检索闭环，本版未在程序内改动模型权重。
