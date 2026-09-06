# pwncraft v0.5.2

## EXP / Heap IR

- 新增 `features/heapviz/analyzer.py`，使用完整模块 AST、安全表达式求值、有限控制流和统一 Heap IR 替换逐行正则主路径。
- 支持多行/分号、位置/关键字、`*args/**kwargs`、方法、别名、wrapper、默认参数、容器索引、append、列表推导式、range/enumerate/zip、有限嵌套循环和 break/continue。
- 支持 show/recv/slice/ljust/u32/u64/int.from_bytes/shift/mask 的值流，保留 source、dependencies、byte width、endian 和 provenance。
- 支持 p32/p64/flat fake chunk 构造识别；循环最多 256 次、语义事件最多 1024 条。
- 未知分支不猜测，用户选择 true/false 后才继续 allocator replay；语法编辑暂时无效时保留最后一次有效时间线。
- 动态 `for/while` 和未映射的堆类调用会生成 `unresolved` 时间线边界，并在该处停止推进，不把后续状态伪装成已证明。
- 250ms 防抖、`QThreadPool` 后台分析和 generation id 防止旧分析覆盖新代码。

## 时间线与场景

- 时间线扩展为 Step、源码、语义、chunk/index、size/data、状态变化、可信度七列。
- 双击/右键支持 replace、ignore、insert before/after、split、merge、clear；EXP 选区可直接绑定为人工语义。
- 校正使用 AST 指纹、源码和循环环境重绑；失配时生成 stale diagnostic。
- 场景 schema 升级为 v2，保存 overrides、branch choices、helper mappings，并兼容读取 v1。
- helper 映射可按当前题目导入/导出 `.pwncraft-helper.json`。

## 内存与画布

- 新增 `MemoryRegion`，区分 known/zero/unknown/metadata 与 observed/derived/inferred/unknown provenance。
- malloc 未初始化尾部不再伪装为 NULL；`PREV_INUSE=1` 时 prev_size 显示 inactive/unknown。
- 已知非零机器字完整展开；只有可证明连续零区间才显示居中的 `··· range / N bytes NULL ···`。
- chunk 卡片增宽、字体/行高/留白增大；轴只绘制 heap base 相对偏移，绝对地址进入 tooltip/详情。
- 双链 bin 保持放大的 `bk | chunk | fd` 圆角节点、fd 上弧、bk 下弧和 arena sentinel。
- 选中 chunk 时 fd/bk/key 字段与 bin 节点精确连线；可按 header/user/fd/bk 种类插入地址。

## 格式化字符串

- 保持“低/高位分解”和“写入 payload”为可独立插入的模块，不强制生成整个 EXP。
- 修正 amd64 `%s` 泄漏模板：格式串位于前部，对齐后再追加 `p64(addr)`，避免地址中 `\x00` 提前截断。

## UI

- 全局默认 115%，支持 100%/115%/130% 与 `Ctrl+-`、`Ctrl+=`、`Ctrl+0`，QSettings 保存比例、窗口和 splitter。
- 启动引导改为目标环境/本题文件/EXP 习惯三张大卡片，实时摘要和就地校验，只保留主操作。
- Heap 画布移除 step/banner/状态徽章等视觉噪音，顶部只显示实际架构、glibc 和状态步数。
- 应用版本更新为 v0.5.2。
