# VALIDATION v0.10.0 — Allocator Truth Closure

## 结果

- Windows Python 3.11 / `QT_QPA_PLATFORM=offscreen`: **186 passed, 1 skipped**（可选 glibc differential harness 在未设置环境变量时 skip）。
- Ruff: **All checks passed**。
- Semantic benchmark: **60/60 whole-case pass，全部 18 项指标 100%**。
- Sunshine corpus: 52 个候选，23 FULL_REPLAY、18 PARTIAL_REPLAY、2 MODEL_READY、9 PARSE_ONLY、0 SEMANTIC_VERIFIED。
- 可进入 allocator 模型的累计比例：`43/52 = 82.69%`；外部 oracle 语义认证：`0/52 = 0%`。没有把 simulator replay 冒充 semantic verification。
- UI audit: 1600×1000 Windows Qt 离屏实渲染已检查；EXP、Physical Heap、Bin/Show 三栏默认完整可见，物理卡片无水平截断，top address/size 可见，字段名与 provenance 不重叠，无 ellipsis。

## 硬验收

1. P=1 阻止 A/B backward consolidate：通过。
2. 正常 footer 写入后 B.prev_size/A size 与 P=0 驱动 backward consolidate：通过。
3. tcache key=0 bypass：通过；正常 key 命中后 memory traversal abort：通过。
4. A overflow 同时生成 top.prev_size/top.size impact：通过。
5. 下一次 malloc 消费修改后的 top.size：通过。
6. partial overwrite 保存 field offset=0、length=1、payload offset、8-byte mask：通过。
7. unsorted fd/bk corruption 在 malloc 消费时形成 `corrupted_double_linked_list`：通过。
8. fake candidate/likely/confirmed：通过；ROP negative：通过。
9. overlap 保持 single memory / multiple typed views：通过旧回归与 benchmark。
10. cache-memory 人工分裂由 `assert_cache_consistency()` 检出且原字节不被 repair：通过。

## 18 个最终问题

1. **完全 memory-driven 的决策**：chunk size/PREV_INUSE/prev_size、backward/forward consolidation 边界判定、tcache key 与 duplicate chain traversal、entry next decode、safe-linking field address、top size split/merge、双链 victim fd/bk reciprocal integrity check、partial/top overwrite effects。
2. **仍依赖 ChunkState 的部分**：逻辑 chunk identity、handle/alias、lifecycle provenance、已知 chunk/address 的定位、regular-bin 可达性一致性检查、UI role/evidence。
3. **仍依赖 Python bin list 的部分**：tcache/fastbin head/count/bucket、unsorted/smallbin/largebin expected ordering 与 size bucket、largebin best-fit/nextsize 保守顺序；均有 divergence 审计，且不会 refresh 覆盖 memory。
4. **PREV_INUSE 是否真正参与 consolidation**：是；当前 chunk P=1 明确阻止 backward merge。
5. **prev_size 是否真正参与 backward consolidation**：是；由 memory 计算 prev address 并校验 prev.size。
6. **tcache key 是否从 memory 读取**：是；concrete zero 不命中 symbolic per-thread key。
7. **tcache duplicate 是否真实 traversal**：是；从 cached head 起步，后续每个 next 都从 PhysicalMemory 解码。
8. **top.size 是否真正决定 malloc**：是；unknown、misaligned、P clear、too-small 都可产生结构化 abort。
9. **top overwrite 是否进入 WriteImpact**：是；top.prev_size/top.size 均进入，含 before/after/mask。
10. **unsorted fd/bk corruption 是否影响 allocator**：是；下一次 victim processing 读取 corruption 并 transition 或 abort；当前安全策略为 abort。
11. **partial overwrite 是否精确到字段 byte offset**：是；保存 offset、实际 length、payload offset/length 与完整字段 changed mask。
12. **overlap 是否一份 memory 多 view**：是；未添加任何 sync-B 逻辑。
13. **fake false positive/negative 变化**：不再依赖变量名；aligned malloc header layout 为 candidate，pointer storage 为 likely，allocator use 为 confirmed；ROP markers/非 size layout 保持负例。结构启发仍可能漏掉高度符号化 header。
14. **semantic benchmark case 数**：60。
15. **whole-case pass rate**：100%。
16. **真实 corpus MODEL_READY 累计比例**：43/52，82.69%（按达到 MODEL_READY 或更高级别计）。
17. **SEMANTIC_VERIFIED 比例**：0/52，0%；缺少独立 pwndbg/runtime oracle，严格不自证。
18. **最大剩余 correctness gap**：服务端隐式/custom allocator behavior profile 与动态 entrypoint；其次是完整 largebin nextsize/version policy、真实 TLS bin heads、multi-arena/mmap/sysmalloc。

## 产物

- `datasets/semantic_benchmark/v0.10.json`
- `artifacts/semantic_benchmark/v010_report.json`
- `artifacts/semantic_benchmark/acceptance_v010.txt`
- `artifacts/sunshine_ast_v010/report.json`
- `artifacts/sunshine_ast_v010/REPORT.md`
- `artifacts/ui_audit/heap_allocator_truth_v010_windows.png`
- `artifacts/ui_audit/canvas_allocator_truth_v010_windows.png`
- `artifacts/ui_audit/allocator_truth_inspector_v010_windows.png`
- `ALLOCATOR_TRUTH_AUDIT_v0.10.md`
