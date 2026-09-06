# v0.20.0

v0.20 大重构第一轮（Phase A/B/C）：**Target-Centric + ZCode 式 Shell + 原生终端体感**。迁移全景见 `docs/plans/MIGRATION_PLAN_v0.20.md`（§101 #1）。

## Phase A：TargetContext 单一真值（§1–§6）

- 新增 `pwnbao/core/session/target.py`：
  - `TargetContext` 全字段 schema（original/working/sha256/架构/保护/interpreter/libc/ld/build_id/source_files/exp_file/revision…）；
  - `import_target()`：原始 ELF 拷贝入 `.pwnbao/original/`（**只读**，权限位剥离写位）+ `runtime/` 工作副本；同目录自动发现 libc/ld（§94）；
  - `primary_path`：工具默认路径 = 工作副本（存在时）。
- **patchelf 只作用于工作副本**：`_start_elf_workflow` 重写为 `import_target → auto_patch_elf(working) → 静态分析(working) → pwndbg(working)`（§5，原件 sha256 永不变）。
- `PwnWorkspace` schema→2：新增 `target` 节 + `set_target()`（发布 `target_changed`，派生镜像继续写 `binary` 节供旧页面/旧项目兼容）；schema=1 旧项目照常加载。
- **删除的重复路径输入（§101 #3）**：
  | 位置 | 变化 |
  |---|---|
  | BinaryPage 路径框 | 只读 + 折叠「高级 Override」（工具级临时，不改变 Target） |
  | ROP Command Builder Binary | 只读，自动 Target |
  | Syscall 页 Seccomp 路径 | 只读，自动工作副本 |
  | Libc 页 libc 路径 | 只读，自动 Target.libc |
  | 任务引导对话框 | binary/libc 字段移除，显示「来自 Target，自动继承」 |
- task_profile 降级：binary/libc 不再由用户输入，写入方唯一为 TargetContext 同步（arch/io 保留为 EXP 习惯）。全删留 Phase F。

## Phase B：ZCode 式 Shell（§7–§11）

- 新增 `pwnbao/gui/shell/`：`activity_bar` / `context_sidebar` / `editor_area` / `inspector_panel` / `bottom_panel` / `breadcrumb` / `import_page`。
- 布局（§95）：`ActivityBar(88) | ContextSidebar(232) | EditorTabs | Inspector(264)` 上、`日志` BottomPanel 下，顶部 breadcrumb `pwn · amd64 · libc …`。
- Activity 六项（§8）：目标/分析/利用/调试/内存/工具；Sidebar 内容树按 §9；「＋导入新 Target」动作入口。
- EditorArea（§10）：IDE 式多 tab，可关闭/拖动排序/右键「固定」，同 key 单例聚焦；**复用 v0.19 全部页面组件**（零业务重写），空工作区初始为「导入 Target」页。
- Inspector（§11/§68）：订阅选择——Gadget（指令/控制寄存器/污染/栈距/评分/来源）、函数/GOT/PLT 符号、Target 摘要。
- EXP 编辑器带工具列作为常开 tab（§55）；HeapViz 不再独占全窗；历史/校准面板默认不占宽度（§29/§85）。
- `Ctrl+O` 全局导入；`Ctrl+K` 面板直达所有 tab key。

## Phase C：Terminal Frontend（§16–§27）

- 新增 `pwnbao/gui/terminal/`：
  - `frontend.py`：`TerminalFrontend` 抽象（对齐既有 TerminalWidget 契约）；
  - `xterm_frontend.py`：**xterm.js 5.3 + fit addon 离线打包**于 `assets/xterm/`（零 CDN，§18）；PTY→JS 8KB/12ms 批量 write（§22）；fit→真实 PTY winsize（§23）；光标/选区/CJK/IME/truecolor/scrollback 全交 xterm（§24/§25）；
  - `legacy_frontend.py`：v0.19 手绘 surface 包装为回退实现。
- 选择策略：设置 `terminal/frontend`（auto/xterm/legacy）；offscreen（自动化测试）恒走 Legacy；PyQtWebEngine 缺失或资产缺失自动回退。
- 复制键位预设（§26）：默认 Windows Terminal（拖选不自动复制、Ctrl+Shift+C/V、右键菜单）；`classic` / `linux` 可在设置切换（xterm 前端由键位映射层承载，legacy 保持 v0.19.2 快速编辑行为）。
- 顺手修复 Legacy 包装器自父 deadlock（`setParent(self)` 会在 Qt 内无限等待）。
- requirements 新增 `PyQtWebEngine>=5.15.7`；`build.py` 打包 `gui/terminal/assets`。

## 测试

- 新增 `tests/test_v020_shell.py`：TargetContext 导入/只读原件/libc 自动发现/schema2 round-trip/schema1 兼容、前端契约（offscreen→Legacy）、Shell 活动数/tab 单例/去重只读断言（默认精简跑；`PWNBAO_SHELL_GUI_TESTS=1` 开启重量级 Shell GUI 断言）。
- 导航探针 `tests/_v015_nav_probe.py` 重写为 Shell 不变量（6 活动、11 注册 key、palette→tab key 路由、单例）。
- 全量回归：**377 passed, 4 skipped**；Heap 语义基准 60/60；py_compile 通过。
- 验收截图（§101 #4/5/8 自动化子集）：`artifacts/ui_audit_v020/01–05.png`（采集脚本 `pwnbao/tools/ui_capture_v020.py`）。

## 现存限制（§101 #16，如实声明）

- xterm 前端需要**真实桌面会话**验证：中文拖选/IME、150/200% DPI、真彩、连续单步 P95（§89/§101 #6/#7/#10–#12）——离屏无法覆盖，本机首跑若遇问题可将 `terminal/frontend=legacy` 立即回退。
- xterm 复制键位三预设：Windows 预设完整；classic/linux 映射在下一小版补齐 GUI 设置项。
- Phase D（Heap PhysicalGrid/EditTransaction）、Phase E（Semantic Lens）、Phase F（FILE Typed View + task_profile/WorkbenchDialog/IOFILE 一级导航清理）未开始。
- 官方 pwndbg 未修改。
