# pwncraft v0.7.0

## Qwen Coder 审计闭环

- 固定 LM Studio 模型 ID `qwen3-coder-30b-a3b-instruct`，默认 `4096 context / 3584 input / 512 output / temperature 0.1 / 180s`。
- 增加 `StrictProposalReplayer`：AI 只能校正 Heap IR，候选必须通过源码 hash、精确字节锚点、字段白名单和独立 allocator replay；snapshot effect 还要证明 current/expected 变化，Pwndbg 证据只能来自真实解析结果。
- 语料批处理保存 raw candidate audit、validator 拒绝、strict replay 和模型耗时，支持 `--split`、`--case`、SHA256 缓存和断点恢复。
- 规则启用门禁为两个独立 case、零负样本和至少一个 holdout 通过；本轮真实语料没有候选满足门禁，因此没有伪造全局规则。

## Allocator truth

- request size 无法由 EXP/Pwndbg 证明时不再复用同一 top 地址，也不把未知大小的 free 猜成 tcache/fastbin/unsorted；使用唯一符号布局并保留 `unknown` bin/fd/bk。
- `AIAnalysisResult` 保留 raw candidate audit，GUI 只读展示被 validator 拒绝的候选和原因，严格校正不会直接写画布。
- unknown-size、严格 replay、Qwen 假服务/离线/超预算和规则晋升均有回归测试。
