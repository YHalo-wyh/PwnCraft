# CHANGELOG v0.10.0 — Allocator Truth Closure

## 核心

- PREV_INUSE、prev_size、next boundary tag 正式驱动 backward/forward consolidation；移除按 freed 邻接直接合并的错误路径。
- tcache duplicate 改为读取 PhysicalMemory.key，key 命中后沿 PhysicalMemory.next traversal；key 清零 double-free bypass 可重放。
- top 成为完整 PhysicalMemory object；malloc/top merge 读取并写回真实 size，top corruption 影响下一次 malloc。
- unsorted/smallbin/largebin 引入 virtual arena bin head；unlink 前从 memory 检查 fd/bk reciprocal relation，损坏形成 AllocatorAbort。
- safe-linking 始终使用 next/fd 的实际 field address。
- `assert_cache_consistency()` 和 `model_divergences` 检测 stale cache，不自动覆盖 corruption。

## 写入、证据与 UI

- WriteImpact/OverwriteEdge 增加 kind、field byte offset、实际覆盖长度、payload length、changed-byte mask。
- top.prev_size/top.size 进入正常 WriteImpact。
- fake chunk 改为 candidate/likely/confirmed 证据级；结构候选不靠变量名，allocator 引用才 confirmed；ROP 保持负例。
- Inspector 展示 abort、divergence、impact kind/offset/length/mask、Writes From/Into、last writer。
- top 行直接显示 address/size；选择 chunk 不再关闭默认 fit，三栏默认宽度完整展示；field identity/provenance 分行，禁止重叠和省略号。

## Benchmark / corpus

- ground truth 扩至 `v0.10.json` 60 case，新增 7 类 allocator truth 指标，whole-case=100%。
- Sunshine 52 EXP 报告分级为 PARSE_ONLY/MODEL_READY/PARTIAL_REPLAY/FULL_REPLAY/SEMANTIC_VERIFIED，并记录具体失败原因。
- 增加可选 glibc C harness differential test；无 gcc/runtime 时 skip。
- 旧测试若假设已初始化 boundary word 是 `inactive/unknown`，已按真实 memory expected 更新。
