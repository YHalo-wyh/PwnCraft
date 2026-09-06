# v0.21.0

v0.20 大重构第二阶段（Phase D/E + Phase F 首项）：**Physical Heap Grid + EditTransaction + Semantic Lens**。

## Phase D：Physical Grid（§30–§36/§78–§82）

- 新增 `pwncraft/features/heapviz/grid/physical_grid.py`：
  - `build_chunk_rows()`：从 chunk 真实布局推导视觉行——`prev_size`(word) / `size`(word) / user rows（每行 2×word，左/右两个 cell，尾行截断）；
  - `intersect_coverage()`：覆盖 = **与既有行的交集**（§33），渲染层只拿 `(row, span)` 对；
  - `covered_fraction()`：行内比例 mask（§36 部分 byte 覆盖）；
  - `virtualize()/rows_touching()`：大 chunk 折叠 + 覆盖触达折叠区时的再展开信号（§37/§38）。
- **P0 修复（+8 细条）**：`heap_canvas._draw_manual_coverage_overlays` 重写——不再按 8 字节堆叠独立小矩形；覆盖渲染 = 在既有 prev_size/size 头行（竖向分段）与 user 行（横向 L/R 比例 tint）内部着色，并画出真实行分隔线。**行数由 chunk 几何决定，与覆盖长度无关**（§90 验收路径：A write extent +8×4 → B.prev_size/size/user L/R 几何不变）。
- 坐标语义修正：grid 用 chunk 相对偏移，渲染层负责 绝对↔相对 换算（头字段默认值/地址列均按此对齐）。

## Phase D：EditTransaction（§74–§77）

- 新增 `pwncraft/features/heapviz/editing/transaction.py`：
  - `EditTransaction`：begin → preview（纯草稿，模型不可观测）→ validate（空范围/payload 越界/自定义校验器）→ commit/cancel；
  - `SemanticPatch`：提交后的语义字节段变更记录；
  - `TransactionStack`：**语义 undo/redo 独立成栈**（布局 undo 不在此栈），应用回调对接 PhysicalMemory。
- manual coverage 的拖拽预览继续虚线呈现；提交路径统一经 `TransactionStack.commit`。

## Phase E：Semantic Lens（§12–§15/§28）

- 新增 `pwncraft/core/lens.py`：Call Convention / Syscall 两类**寄存器角色表**（amd64/i386/aarch64），事实来源 = ABI 常量 + 真实 syscall 表（含 `SYS_x = 号`、i386 栈传参说明、amd64 `R10 而非 RCX` 等）；`render_lens()` 输出中文解释。
- 新增 `gui/debugger/lens_panel.py`：Debug 工作区右侧可折叠面板（§28），Syscall/Call 两模式切换，架构自动继承 Target；**只渲染事实，不猜利用意图**（§15/§71）。
- pwndbg-mogai 原生发布 `register_roles` 的 bridge（§70）待接，当前角色表为 ABI 常量而非终端解析。

## Phase F 首项清理（§97）

- 命令面板未知条目不再回落 legacy WorkbenchDialog，统一走 Shell tab 注册表。

## 测试

- 新增 `tests/test_v021_grid_lens.py`（11 项）：canonical 行布局/尾行截断/覆盖交集仅触既有行/比例 mask/虚拟化折叠、事务生命周期/非法 payload 拦截/语义 undo-redo、三架构 lens 事实断言。
- 全量回归：**388 passed, 4 skipped**；Heap 语义基准 60/60；py_compile 通过。

## 现存限制

- `virtualize()` 模型就绪但画布尚未默认启用折叠（大 chunk 仍全展开渲染）。
- 覆盖写入（cell 点击 → payload → PhysicalMemory）的 UI 事务化已具备 TransactionStack，逐 cell inline editor 的接入留待下一小版。
- mogai 原生 register_roles bridge 未接；Lens 当前为 ABI 常量事实。
- Phase F 剩余：task_profile 全删、FILE Typed View。
