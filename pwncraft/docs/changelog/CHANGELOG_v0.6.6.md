# pwncraft v0.6.6

## 本地 AI 实机接入

- 已在 i9-14900HX / 32GB / RTX 4060 Laptop 8GB 上接入 LM Studio `qwen3.6-27b`。
- LM Studio 当前加载参数：4096 context、parallel=1、GPU offload=35%、不加载 mmproj；API 为 `http://127.0.0.1:1234/v1`。
- pwncraft默认改为手动模式、4096 context、3200 input、768 output、temperature 0.1、300 秒超时。
- 新增 JSON assistant prefill。对 Qwen3.6 实测可跳过大量 `reasoning_content`，直接进入受 JSON Schema 约束的答案。
- AI wire schema 每次只取最高价值的两个候选，并使用紧凑 `payload_json`，进入公开模型前会还原并经过原有严格校验。
- Prompt/cache 版本升为 `pwncraft-heap-ai-v2`，不会复用旧 wire schema 的缓存。

## 提示压缩

- 完整 EXP 始终保留，不静默截断。
- 静态 Heap IR 改为带 Step、源码行、字节范围和证明字段的紧凑时间线；连续循环折叠为 repeat/首尾差异。
- 去掉 operation note、重复 source/expression、完整 binding JSON 等重复信息。
- 全局规则压缩为 matcher/output；已有精确规则时不重复发送对应 few-shot。
- `traditional/solve.py`（133 行、2908 bytes、56 个语义事件）在装入两条反馈规则后，GUI 真实请求预算为 3162/3200 input tokens。

## 模型反馈闭环

- 实测模型识别出 `add(size,idx)` 为 alloc，置信度 0.98。
- 校正模型把形参名误放入 `keywords` 的问题后，以 modified 反馈写入本地知识库。
- 模型第二候选的 `len` 角色未通过白名单；按 helper 的 send 顺序校正为 `length`，保存 `copy(src,dst,len)` 精确规则。
- 新增常见 AI 角色别名归一化（如 `idx -> index`、`len -> length`），归一化后仍必须通过 validator。
- 修复全局签名规则跨题污染：带 `parameter_names` 的位置参数规则只有在当前 EXP 存在完全一致的 helper 定义时才应用。

## 静态语义修复

- 嵌套 `u64(show(...))` 现在保持真实 Python 执行顺序：先 show，再 derive value。
- 普通 `p64(0) + flat(ret, pop_rdi, ...)` ROP 链不再被误判为 fake chunk。
- 保留手工语义操作、时间线、函数适配和严格 allocator 为事实核心；AI 仍只产生候选。
