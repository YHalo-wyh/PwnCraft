# v0.9.0

## 核心架构

- 新增稀疏 `PhysicalMemory`、符号/绝对 `MemoryAddress`、`MemorySpan/Object/Snapshot` 与逐范围 provenance。
- 新增 `PayloadIR/PayloadSegment` 和安全 AST evaluator，覆盖 pack、concat、repeat、flat/fit、padding、slice、join、to_bytes、struct.pack。
- 所有 alloc/edit payload 都落到物理内存；跨 chunk overflow 与 off-by-one 会自然改写相邻 metadata。
- 新增 `WriteEvent/WriteImpact/OverwriteEdge` 及累计写历史，支持查询谁从 payload 的哪个 offset 覆盖了哪个字段、before/after。
- `ChunkMemoryView` 从 memory 读取 allocated/tcache/fastbin/doubly-linked/largebin/fake 字段；safe-linking 同时给出 stored 和 decoded。
- allocator 的 size/bin 选择优先读取物理 size word；regular free 写 boundary tag，tcache/fastbin 按真实行为不清 PREV_INUSE。
- 移除 `_pending_target_by_size`。poisoned next 在 pop 时由 PhysicalMemory 解码并成为 freelist external head，后续 malloc 消费该 head。
- singly linked bin refresh 不再覆盖 EXP 已写入的 next 字段。
- overlap scene group 明确表示 one physical memory / multiple typed views。
- sparse span/address/object index 与 enriched-view cache 将 1024 个 alloc + 全时间线 snapshot 的参考重放降到约 11.9 秒，避免 per-byte object 和旧版重复全量解释。

## 准确性与 UI

- packed ROP 不再因为“多个 p64 + 第二字像 size”被误报成 fake chunk；只有明确 allocator 语境才提升视图。
- Chunk detail 增加 original/current size、view kind、top 物理信息、当前写事件、累计 Writes From/Into 和最后 writer。
- Canvas 对本步骤被覆盖字段做静态高亮，不增加干扰动画。

## Benchmark 与测试

- 新增 `datasets/semantic_benchmark/v0.9.json` 八个 ground-truth case。
- 新增 `python -m pwnbao.tools.heap_semantic_benchmark`。
- 新增 PhysicalMemory、PayloadIR、overflow、off-by-one、safe-linking、poison、overlap、regular-free boundary tag 与 benchmark 测试。
