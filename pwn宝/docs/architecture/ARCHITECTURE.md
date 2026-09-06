# pwn宝 架构

> v0.15 架构增量：主界面收敛为左侧一级导航 Workbench（Dashboard/Binary/Stack/Heap/ROP/Libc/Format/Syscall/Debug/EXP/Tools），所有新页面只读写共享 `PwnWorkspace`。QUERY 工具链 `CliToolService`（CLI 注册表 → WSL 执行 → 严格解析器 → Workspace 入库）保证 stdout 永不直接成为 GUI；`ActionType` 在注册层禁止 QUERY 工具插入 EXP。Heap Canvas 以 PhysicalMemory 为唯一真值；已有 Chunk 是不可移动的物理锚点。调试器为 `third_party/pwndbg-mogai` 独立源码 Fork。

> Workbench 数据流：Binary/ROP/Syscall 页 → `CliToolService.execute_only`（worker 线程只计算）→ GUI 线程 `apply_tool_outcome` → Workspace 事件 → 相关页增量刷新。调试器联动只经 `DebuggerWorkspace.send_command()` 下发到真实 pwndbg-mogai 终端。

> v0.13.2 Heap Canvas / Debugger 数据流见 `DEBUGGER_ARCHITECTURE.md`；Canvas 约束见 `HEAP_CANVAS_EDITING.md`。

## v0.10.2 presentation and runtime bridge

- `HeapCanvas._draw_overlap_blocks()` 以真实 chunk 数值边界切分物理区间：单 owner 段直接绘制所属 chunk 色，`owners >= 2` 的交集段绘制独立 overlap 色。这些色块位于 chunk body 内，不增加 separator、lane 或 card gap。
- `_is_exploit_overlap()` 先区分 allocator reuse 与漏洞覆盖：同一 physical object 上一旧一新的 stale/live view 属于正常复用，不换色；并发非 stale view、不同 physical object 相交、cross-chunk OverwriteEdge 或明确 overflow/fake/House 证据才进入 overlap 着色。
- exploit overlap 组只绘制一张物理内存卡，所有并存 logical view 在 header 第二行以稳定色签保留；普通复用组只显示最新 live chunk。界面不使用 `QGraphicsProxyWidget` 或“覆盖”按钮。
- `theme.py` 是 paper/ink/khaki/clay/sage/mist 设计 token 的唯一入口。按钮高度、页签导航、字段行、地址轴和 splitter 采用紧凑密度。
- 自动 fit 同时考虑 scene 宽高；达到 0.58 可读下限后才允许大 trace 滚动。Bin/Show 继续拥有独立 scene 和滚动状态。
- `elf_runtime.py` 发现同目录 loader/libc，调用 `wsl.exe --exec patchelf` 原位修改 ELF，然后独立验证 interpreter、rpath 和 needed；任一失败恢复 `.bak.*`。
- `pwndbg_manager.py` 固定 `2026.07.29` x86_64 portable asset/SHA256，按需安装到 WSL 用户数据目录。`PwndbgBridgePanel` 使用 `QProcess` 保持交互会话，每次停下后抓取 heap/bins marker block。
- `MainWindow._on_live_pwndbg_snapshot()` 是 runtime 证据到 HeapViz 的单向同步边：快照只作为 `CALIBRATED` diff，不会静默改写 allocator 模拟真值。

## 事实流

```text
EXP Source
  -> Python AST / Program Semantic IR
  -> PayloadIR
  -> AllocEvent / FreeEvent / ReadEvent / WriteEvent
  -> PhysicalMemory
  -> Typed allocator reads (boundary tags / tcache / bin heads / top)
  -> glibc policy transition
  -> TypedMemoryView
  -> HeapSnapshot / Scene / Timeline / Canvas
```

`PhysicalMemory` 是新 replay 的物理事实中心。`ChunkState`、`MemoryRegion`、bin 节点和 fake chunk 都是兼容视图，不拥有另一份互相独立的字节真值。旧场景缺少 memory snapshot 时仍可保守读取旧字段，但必须显示 unknown/inferred，不能制造字节。

## PhysicalMemory

`pwnbao/features/heapviz/memory` 使用稀疏 span，而不是每字节一个 Python 对象：

- `MemoryAddress` 支持绝对地址与 `heap_base/libc_base/stack` 等符号根加偏移；不同根不别名。
- `MemorySpan` 保存连续 bytes 或定长 symbolic value、状态与 provenance。
- 写入只切分相交区间；相邻且 provenance 相同的物理 byte span可以合并。
- `MemoryObject` 是物理范围标签。多个 `ChunkMemoryView` 可以覆盖同一组 spans。
- snapshot 不可变，GUI 与 diff 不会反向修改 allocator。

## PayloadIR

`PayloadEvaluator` 只解释安全 Python AST，不调用 EXP 函数。每个 `PayloadSegment` 保存 offset、length、raw/symbolic value、endianness、source expression 与 confidence。构造边界不会因相邻 bytes 相同而丢失。

稀疏 `flat/fit` 的空洞也是实际发送的字节：显式单字节 filler 可得到 raw bytes；默认 cyclic filler 只标为 inferred symbolic，不猜具体字节。

## 写入与覆盖因果

每次 program payload write 生成 `WriteEvent`。物理写入与所有 typed field 范围求交，产生 `WriteImpact` 和 `OverwriteEdge`：

```text
writer operation / source chunk / source pointer
payload offset
physical [start, end)
target physical object / chunk / field
before -> after
confidence
```

snapshot 同时保留当前 step 的高亮边和累计 history，因此之后的 step 仍可查询字段的最后 writer。

## Allocator Truth Closure

唯一字节真值是 `PhysicalMemory`。allocator 每一步按“读 typed memory -> 判定 -> 最小写入 -> 下一步再读”推进。`ChunkState` 已降级为逻辑身份、handle、provenance 和 UI cache；Python bin list 是 arena head/count/bucket 的加速缓存，不得覆盖程序写入。

`Model Divergence` 表示 cache 与 memory 分裂。自动 snapshot 会记录，测试可调用 `assert_cache_consistency()` 强制失败；检测绝不执行 repair。`AllocatorAbort` 是 snapshot 的正式字段而非 warning 文案。

## Memory-driven decisions

- `request2size` 使用 `SIZE_SZ` 和对应架构对齐。
- chunk size 首先读取 `PhysicalMemory[chunk+SIZE_SZ] & ~7`。
- tcache/fastbin entry 的 next 在 free 插入时写入物理内存；malloc pop 时从实际 field address 读取并 safe-link decode。tcache double-free 先读 entry.key，key 命中后才从 head 沿 PhysicalMemory.next 遍历。
- poisoned pointer 成为 freelist 的真实 external head；下一次 malloc 消费 head。不存在 `_pending_target_by_size`。
- tcache/fastbin free 不清后继的 `PREV_INUSE`；普通 free 写 next.prev_size 并清 flag。backward merge 由当前 size.PREV_INUSE 与 prev_size 决定，forward merge 由后继边界位决定，不扫描 lifecycle 代替 header。
- top 是完整 `MemoryObject/TopChunkView`；malloc 读取 top.size、校验并分裂，top overflow 会形成 WriteImpact 并改变后续 malloc。
- unsorted/smallbin/largebin 拥有 virtual arena `BinHeadView(fd/bk)`；victim unlink 前读取 PhysicalMemory 并检查 reciprocal link。链表修改由纯 `insert_doubly/remove_doubly` transition 生成最小 `LinkMutation`；每个 mutation 才写入 `PhysicalMemory`，不会在 refresh 时重算并覆盖程序破坏的 fd/bk。
- fastbin 与 smallbin 在 tcache 未满时实施 refill；每一次 pop/refill/insert/remove 都保留 `BinTransitionEvent`。
- largebin 对不同 chunk size 的代表节点维护保守的环形 `fd_nextsize/bk_nextsize`；它是 CTF 可观测子集，不声称等价于 libc 源码的所有 bucket 和 tie-break 细节。
- strict 模式中的 exploit 名称是 annotation/intent；`MALLOC_TO_TARGET` 不会直接传送 allocator。

当前 glibc 模型仍是 CTF 可观测子集，不是 libc 源码级完整实现。unsorted/smallbin/largebin/top 的进一步精确化通过 `GlibcPolicy` 分层推进。

## Memory-driven 与 cache-driven 边界

| 行为 | 决策真值 | Python cache 的角色 |
|---|---|---|
| chunk size / P bit / prev_size | PhysicalMemory | ChunkState 仅身份/显示 |
| tcache duplicate | memory key + memory next traversal | head/count cache |
| tcache/fastbin pop | head cache + current node memory next | bucket/head cache |
| unsorted/smallbin/largebin unlink | memory fd/bk + arena head | bucket/order expected cache |
| top split/merge | memory top.size/header | `_next_offset` 仅 top address cache |
| overlap | 一份 PhysicalMemory | 多个 typed view |

## Typed views

`ChunkMemoryView` 按 allocator 状态选择 allocated、tcache、fastbin、doubly-linked、largebin 或 fake view，并从同一 memory snapshot 读取：

- `prev_size`, `size`
- `next` stored/decoded、`key`
- `fd`, `bk`
- `fd_nextsize`, `bk_nextsize`
- user bytes

safe-linking 明确展示 field address、stored value、decoded value 和公式。未知 bytes 保持 unknown。

## Provenance

可信度从高到低：

- `observed`：外部实时观测，例如明确校准的调试器字节。
- `calibrated`：由观测映射到静态状态。
- `derived`：由源码、明确表达式或 allocator rule 确定性推导。
- `inferred`：长度/布局可证，但内容或语义不完全可证。
- `assumed`：用户或演示模式明确提供的假设。
- `unknown`：没有证据。

AI 候选不能升级成 observed，也不能把 unknown 内存改写为 NULL。

## 表现层分区

`HeapPanel` 的右侧使用内层水平 splitter 承载两个独立 scene：

- `HeapCanvas` 只渲染地址轴、物理 chunk、typed field、top 和非堆目标；
- `BinShowCanvas` 统一渲染 bin 链与 `ValueObservation` 卡片。

两个 view 共享同一个 `HeapSnapshot` 而不共享 scene/scrollbar。点击任一 bin 节点会以 `chunk_id` 同步主堆选中和 inspector，但不画跨 widget 长对角连线。独立使用 `HeapCanvas` 的外部集成仍可保留旧的 all-in-one 模式。

v0.9.3 的默认布局状态使用 schema 9：外层 EXP/visual 约 `500/1000`，内层 physical/evidence 约 `700/300`。schema 8 的过宽 Bin/Show 状态不会被继承。两个 scene 分别按 viewport 做有下限的水平 fit；主堆下限为 `0.72`，Bin/Show 为 `0.58`，手动 zoom 会退出自动 fit。

Canvas 文本的不丢失约束高于单个 cell 的固定宽度。`_cell_value` 保留旧 `elide` 参数以兼容调用者，但其语义是“在宽度内自适应字号”，不再生成 Unicode ellipsis。字号到 7pt 仍容纳不下时，保留原文本并扩展 scene bounds。Chunk role 使用 header 第二行，避免与 index/size 列重叠。

空模型也是权威结果：对只包含 shellcode 构造和 tube IO 的 EXP，Program IR 可保留调用证据，但只要没有可证明的 heap operation，allocator 就只返回 initial snapshot，不从 payload 字节猜测 chunk。

## Benchmark

`datasets/semantic_benchmark/v0.10.json` 是当前 ground truth corpus，包含 60 个独立标注案例。`SemanticBenchmarkRunner` 分别统计 Operation Precision/Recall/F1、Argument Accuracy、Payload Span Accuracy、Write Range Accuracy、Overwrite Field Accuracy、Allocator Checkpoint Accuracy、Bin Membership Accuracy、Field Value Accuracy、Bin Transition Accuracy、Metadata/Consolidation/Tcache Duplicate/Top/Freelist/Integrity Abort/Partial Overwrite Accuracy 和 Whole Case Pass Rate。

Whole Case 只有在该 case 的所有声明事实都通过时才通过；脚本不崩溃不计成功。

## Remaining correctness boundary

完整 glibc largebin nextsize tie-break、多 arena/mmap、真实 tcache TLS head 的二进制布局、所有版本的 sanity check、服务端隐式 allocator 行为仍未等价实现。遇到这些情况必须保持 partial/unknown 或使用标记为 `CALIBRATED` 的 pwndbg/runtime oracle。
