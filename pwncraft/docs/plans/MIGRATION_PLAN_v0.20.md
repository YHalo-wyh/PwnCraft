# MIGRATION_PLAN_v0.20 — Target-Centric Pwn Workbench

> 目标（§100）：**Single Target · Single Truth · Native Terminal · Physical Heap · Contextual UI**。
> 拖入一个二进制 = 进入围绕该 Target 的完整工作区；静态分析 → Exploit 构造 → 内存模型 → pwndbg-mogai 动态调试全程同一上下文。

本计划把 v0.20 拆为 A–F 六个阶段。**每阶段有独立验收；未列绿不得宣称完成。**

---

## 阶段总览

| Phase | 内容 | 状态 |
|---|---|---|
| A | TargetContext 单一真值 + 单一导入入口 + 删除重复路径输入 + task_profile 降级 | 本轮 |
| B | ZCode 式 Shell：Activity Bar / Context Sidebar / Editor Tabs / Inspector / Bottom Panel | 本轮 |
| C | TerminalFrontend 抽象 + XtermFrontend（xterm.js 离线）+ Legacy 回退 | 本轮 |
| D | PhysicalGridModel + EditTransaction + 删除 manual coverage 语义真值 + 两种 Drag Handle | 下轮 |
| E | Semantic Lens（Call/Syscall 角色表 + Debug 右侧面板）；mogai 原生发布 bridge 待接 | ✅ v0.21（bridge 待接） |
| F | FILE → Typed View + 技术债清理（task_profile 全删 / WorkbenchDialog fallback / IO FILE 一级导航） | ✅ v0.25 |

---

## Phase A：TargetContext（本轮）

### 数据模型（§101 #2 schema）

```python
TargetContext:  # pwncraft/core/session/target.py
    target_id: str            # sha256 前 16 位
    original_binary: str      # 只读原件路径（禁止 patchelf）
    working_binary: str       # .pwncraft/work/runtime/ 工作副本（唯一允许 patch 的文件）
    sha256: str
    file_name: str
    project_root: str
    architecture: str         # amd64 / i386 / aarch64
    bits: int
    endian: str
    osabi: str
    entry: int
    pie / nx / canary / relro: str   # ON / OFF / FULL / PARTIAL / UNKNOWN
    interpreter: str
    libc: str                 # 同目录自动发现（§94），或 Inspector 手动添加
    ld: str
    libc_version: str
    build_id: str
    source_files: list[str]
    exp_file: str
    static_revision: int      # 每次静态分析 +1
    runtime_revision: int     # 每次运行时快照 +1
```

- `PwnWorkspace` 新增 `target` 节（schema=2，旧 .pwncraft 兼容加载），`set_target()` 发布 `target_changed`。
- `binary` 节保留为派生镜像（过渡期），最终写入方只有 TargetContext 同步器。

### 单一导入（§2）

- 空 Workspace 中央 DropZone（拖 ELF / 目录 / Ctrl+O / 点击选择）。
- ELF + 同目录 libc/ld 自动绑定；目录导入时自动识别主 ELF。
- 导入完成 → 自动打开 Binary Overview tab。

### 原始只读 + 工作副本（§5）

- `.pwncraft/work/original/` 存原件；`runtime/` 存 patch 后副本。
- `auto_patch_elf` 一律作用于 working copy；原件 sha256 永不变。

### 删除的重复路径输入（§101 #3 清单）

| 位置 | v0.19 行为 | v0.20 行为 |
|---|---|---|
| BinaryPage.path 输入框 | 手填 | 只读展示 + 折叠高级 Override |
| RopCommandBuilder.binary | 手填 | 自动 target.working_binary |
| SyscallPage.seccomp_path | 手填 | 自动 target.working_binary |
| LibcWorkspacePanel.libc_path | 手填 | 自动 target.libc；缺失时「+ 添加 libc」 |
| 任务引导对话框 binary/libc 字段 | 手填 | 移除（arch/io 名保留为 EXP 偏好） |
| Debug 页拖 ELF | 重选 | 默认重析当前 Target；拖入新 ELF = 切换 Target |

### task_profile 降级（§6）

- 唯一写入方：TargetContext 同步器（arch/bits/libc_version/io_name）。
- heap_panel / iofile 的 `profile_provider` 改读 workspace.target。
- 彻底删除（类型、QSettings 持久化、引导对话框重构）→ Phase F。

## Phase B：ZCode 式 Shell（本轮）

- 目录 `pwncraft/gui/shell/`：`activity_bar.py`、`context_sidebar.py`、`editor_area.py`、`inspector_panel.py`、`bottom_panel.py`。
- 布局（§7/§95）：`ActivityBar(56) | Sidebar(240) | EditorTabs | Inspector(280)` 上、`BottomPanel(240)` 下。
- Activity 六项（§8）：Target / Analyze / Exploit / Debug / Memory / Tools；Sidebar 内容树按 §9。
- EditorArea：QTabWidget 可关/可拖/右键固定；tab 注册表同 key 单例；**复用 v0.19 全部页面组件**。
- Inspector（§11/§68）：订阅 SelectionModel；先支持 gadget/chunk/symbol/generic 四类模板，其余类型逐步接入。
- Breadcrumb（§65）：`pwn · amd64 · libc 2.35`，点击弹 Target 详情。
- BottomPanel：Terminal（pwndbg 嵌入）/ Logs；§29 历史/校准面板默认不占位。

## Phase C：Terminal Frontend（本轮）

- `pwncraft/gui/terminal/frontend.py`：抽象接口 = 现有 TerminalWidget 对外契约（feed/clear/focus/selected_text/insert_command/submit_inserted/set_command_catalog + bytesTyped/commandSubmitted/terminalResized）。
- `xterm_frontend.py`（§18–§26）：
  - QtWebEngineView + **仓库内** `assets/xterm/`（xterm.js + addon-fit UMD，实现期从 npm registry 落盘，运行时零网络）；
  - PTY → JS 批量 write（8–16ms / 8KB 合批，§22）；
  - fit addon → rows/cols → transport.resize（§23）；
  - 光标/选区/IME/truecolor 全交 xterm；复制键位三预设（windows/linux/classic，§26）；
- `legacy_frontend.py`：包装现有 TerminalWidget，保底回退（PyQtWebEngine 不可用或 assets 缺失时自动降级）。
- DebuggerWorkspace 只面向抽象；现有 18 项终端测试在 Legacy 路径下保持全绿。

## Phase D（下轮）：Heap PhysicalGrid

- `features/heapviz/grid/`（physical_grid/cells/projection/coverage）+ `editing/`（transaction/size_edit/write_extent/validation）+ `gui/heap/`（chunk_item/row_item/coverage_overlay/handles）。
- 核心（§30–§49、§74–§82）：8 字节是 cell 内量子不是新 row；coverage=对既有 PhysicalCells 的 tint mask；manual coverage 降级为 pending draft；Layout Drag ≠ Semantic Edge Drag；size snap 按 MALLOC_ALIGNMENT、write extent 按 SIZE_SZ；EditTransaction begin/preview/validate/commit；Layout undo 与 Semantic undo 分离；大 chunk 折叠 + overlap 自动展开。
- 验收（§90–§92）：A write extent +8×4 → B.prev_size/size/user L/R 原几何不变；size corruption overlap 由 PhysicalMemory header 重解析产生；`+` 只展开真实物理行。

## Phase E（下轮）：Semantic Lens

- Call Convention Lens / Syscall Lens（§12–§15）：amd64/i386 architecture-aware；数据由 pwndbg-mogai 原生发布结构化 register_roles（§70），GUI 只渲染；不猜利用意图（§15）。
- Debug Inspector（§28）：右侧寄存器/调用/栈视图，可折叠。

## Phase F（下轮）：FILE Typed View + 清理

- FILE → Memory/Typed Views 入口（§50–§52/§84/§96）。
- 清理（§97）：task_profile 全删、legacy WorkbenchDialog fallback、custom TerminalWidget 默认路径、manual coverage 语义状态、IO FILE 一级导航。

---

## 性能预算（§87/§88）

- 终端 P95 额外 UI latency < 20ms（连续 ni/si）；1MB stdout 合批不逐字符跨通道。
- Heap Layout Drag 60 FPS（不重放 allocator）；Semantic Preview < 16ms；快照 GUI 侧 < 150ms。

## 验收对照（§89–§96）

自动化可覆盖：Target 继承（§93）、libc 自动发现（§94）、重复输入删除、布局结构（§95）、核心回归。
必须人工验证：中文拖选/IME、150/200% DPI、真彩、连续单步手感、屏幕截图集（§101 #4–#12）。
