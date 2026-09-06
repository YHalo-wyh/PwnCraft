# v0.9.1

## 右侧 Heap/Bin 证据视图

- 右侧画布默认使用浅色详细视图，每个机器字分开显示 offset、字段名、精确值、provenance 和语义。
- 移除画布中由 `operation.data` 生成的 `payload:`/`payload expr:` 概要；只有 `PhysicalMemory` 的 bytes/symbolic span 才能成为卡片内容。
- 已知非空内容按机器字全部展开，超长内容换行并增加行高，不使用省略号。
- malloc 未写入区域显示 `unknown / not observed`，并按真实开始偏移标记 `user[n]`；只有可证明的连续零字节才显示居中 NULL fold。
- chunk header/user 边界与 allocator/top 重叠会在同一物理地址展示，不再把相邻同 provenance 的元数据误合并成一个大字段。
- 地址轴仅显示 heap-base-relative offset；绝对地址保留在 tooltip/详情，避免和卡片文字拥挤。
- 窄视口将 bin/value-flow 放在物理堆之后，保持 alloc/free 前后 chunk 纵向位置稳定；该布局不绘制穿过多个 chunk 的长对角连线。
- 双链 bin 使用完整 `bk | node | fd` 文字和上下弧线；chunk/sentinel 标识会扩宽节点而不被 elide。

## allocator 链表语义

- 新增纯 `insert_doubly` / `remove_doubly` transition 模型，输出最小 `LinkMutation` 集合。
- unsorted/smallbin/largebin 只将当前 transition 需要的 fd/bk 写入 `PhysicalMemory`；普通 refresh 只读取，不再抹除 UAF/溢出导致的链指针破坏。
- 新增 `BinTransitionEvent`，保留 tcache/fastbin push/pop、doubly insert/remove 和 refill 的可回放证据。
- 实现 fastbin 命中后的 tcache refill，以及 smallbin tail 分配后的 tcache refill。
- largebin 不同 size 代表节点维护保守的 `fd_nextsize/bk_nextsize` 环，且只在关系改变时重写。

## Benchmark 与测试

- ground-truth corpus 升级为 `datasets/semantic_benchmark/v0.9.1.json`，从 8 例扩展到 12 例。
- 新增 Field Value Accuracy 和 Bin Transition Accuracy。
- 新覆盖 fastbin/smallbin refill、largebin nextsize 代表环和“链破坏不被 refresh 撤销”。
