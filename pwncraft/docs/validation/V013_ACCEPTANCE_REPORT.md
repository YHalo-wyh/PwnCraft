# v0.13.2 颜色终端与物理覆盖验收

## 结果

- Python 回归：`266 passed, 1 skipped`。
- Ruff：通过。
- Fork 独立加载：205 个 Pwndbg 命令，要求的 upstream/fork 命令无缺失。
- UI 截图：`artifacts/ui_audit_v013/` 共 28 张。
- GUI 性能：`artifacts/ui_audit_v013/performance.json`。
- 独立/Embedded 真 PTY：`artifacts/ui_audit_v013/pwndbg_interactive_performance.json`。
- Windows 单文件构建：`dist/pwncraft.exe`，60,256,304 bytes，SHA-256 `b589fb93dbd8ee82d6a995d4fad619a8c812589f981ed1681b37d2269ff677e8`。
- 冻结包清单确认携带完整 Fork；5 秒 GUI 启动冒烟通过；冻结 EXE 内 `wsl.exe` 调用返回 0，未再出现 `0xc0000142`。

## 核心验收

- 顶部重复菜单已隐藏并清空；下方 `Exp 编辑/堆可视化/Pwndbg/IO FILE/日志/诊断` 保留。
- `pwndbg-mogai.15` 在 Fork 内强制开启 ANSI 颜色，寄存器、变化值、标题、指令、栈/堆/代码地址分色；Tutor、Slash 仍来自独立源码 Fork，GUI 不做文本映射或二次配色。
- CJK 由独立字体按 terminal 双 cell 绘制，截图 `pwndbg_text_spacing.png` 无融合。
- Pwndbg 页面支持鼠标滚轮按 3 行滚动，右侧可见滚动条与 HistoryScreen 双向同步；已删除工具栏宣传文案。
- 普通 `ni/si` 不触发 Heap snapshot；stop callback 无 heap/bins 扫描。
- Canvas 默认只读；编辑模式才显示 inline editor、合法行 `+` 和上/下覆盖延伸手柄；禁止 chunk 平移、纵向拖动与横向缩放。
- 拖动边缘的 chunk 始终是覆盖主体，只记录上溢/下溢字节范围，不改变原 chunk 地址或 `chunksize`；被覆盖 chunk 的名称头行和精确字节区域使用覆盖色。
- 覆盖区默认为空，点击后可编辑；提交后写入 `PhysicalMemory` 并标记 `CROSS_CHUNK_OVERWRITE` provenance。`+` 仅展开真实行并重排显示，不改物理布局。
- Chunk Size/flags/raw 双向同步，修改后重建 typed view、extent、relations、bins/top/SHOW/Inspector 并一次 commit。
- normal reuse 不染 overlap；视觉碰撞不染 overlap；cross-write/physical overlap 只染真实 byte span。

## 性能结果摘要

- Embedded terminal 100 次 context burst：平均 12.866 ms，P95 21.837 ms。
- 真 PTY 100 `ni`：standalone P95 10.011 ms；embedded relay P95 17.550 ms。
- 真 PTY 50 `si`：standalone P95 12.168 ms；embedded relay P95 10.503 ms。
- 100 chunk render P95 62.839 ms；drag P95 3.812 ms。

## 当前限制

- Fork 依赖固定 x86-64 portable Pwndbg runtime；异构 ELF 默认静态安全模式，动态调试需匹配的 remote/QEMU target。
- glibc allocator 仍是 CTF 可观测子集，不声称覆盖所有 multi-arena/mmap/largebin tie-break。
- GDB 本身拒绝以 `/` 开头的 command name，因此交互 Slash 由 Fork 自带 PTY input framework 截获，再进入 Fork 的 `slash-native`；不经过 Qt。
