# v0.9.3

## 三栏默认布局

- HeapViz 外层 EXP/visual 默认改为 `500/1000`，中间视觉工作区获得更多宽度。
- 内层 Physical Heap/Bin Show 默认改为 `700/300`，收窄右侧、扩大中间物理堆。
- 地址轴从 184px 收窄为 136px，仍显示完整 heap-relative offset，绝对地址保留在 tooltip。
- 物理堆卡片基准宽度从 680 调整为 620；EXP 等宽字号从 15 基准收紧为 13。
- 主堆与 Bin/Show 独立按 viewport fit-to-width，宽度不足时才等比缩小文字；手动 zoom 后不再自动覆盖。
- 布局设置升级为 schema 9，一次性迁移掉 v0.9.2 过宽的右栏存档；新的内层 splitter 位置可持久化。

## 真实 EXP 识别回归

- 校验“霄元杯 Magic Numbers” EXP：`bytes.fromhex -> ljust(0x280) -> sendlineafter/sendafter -> i386 ORW shellcode`。
- 静态结果为 0 个 heap operation、1 个 initial snapshot、0 chunks、0 handles、所有 bins 为空；这是题目的精确结果，不是识别失败。
- 新增界面空模型说明：没有可证明的 alloc/free/edit/show/copy 时，明确拒绝根据 payload/注释伪造 chunk/bin。
- 新增 false-positive 回归，确保 `bytes.fromhex`、`SC.ljust`、`io.sendlineafter`、`io.sendafter` 和 `io.interactive` 不被当成堆 helper。
