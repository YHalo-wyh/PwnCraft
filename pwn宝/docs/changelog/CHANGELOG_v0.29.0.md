# CHANGELOG v0.29.0 — Electron Workbench 全量迁移（Phase B）+ 堆画布 PhysicalGrid 重构

> 日期：2026-08-29。上一版本 v0.28.0（Electron Phase A：壳 + 桥 6 方法）。
> 本版本把全部功能面迁入 Electron Workbench，重构堆演示为「真实 allocator 仿真 + 物理引擎动画」，
> 打通画布校正→识别学习的闭环，调试终端改为直接新开 pwndbg-mogai 实例，
> 并按用户规格把堆画布渲染重构为 PhysicalGrid（固定 cell + CoverageSpan ∩ Cell 着色）。

## 〇、堆画布 PhysicalGrid 重构（用户规格，最终形态）

用户明确给出目标渲染模型（A 向下覆盖 B 逐 +8 的例子），本轮落地：

- **视觉行结构由物理范围固定**：每 chunk 渲染为真实内存方格 —— `+0x00 prev_size`（整行单格）、
  `+0x08 size`（整行单格）、user 区每行两个 qword 格（amd64 每格 8 字节），格内打印物理范围
  （如 `0x5555555592a0 ~ 0x5555555592a8`）与值；格与格紧贴、直角无圆角、无浮空卡片。
- **覆盖 = Paint Mask，不是新横条**：溢出只做 `CoverageSpan ∩ Cell → 格内着色`
  （红色斜线 hatching，按被覆盖子区间按宽度比例绘制）。A 逐次 +8 依次盖住 B 的
  prev_size / size / user qword0 / user qword1，行结构一步都不变。
- **数据来自引擎**：`HeapVisualModelBuilder` 的 PaintSpan（cross_write/physical_overlap）
  + `OverwriteEdge`（含 target_field 与物理区间），覆盖范围是 memory provenance 推导的事实。
- **虚拟化**：长 chunk 只渲染前 2 行 + 尾行，被覆盖的行自动重物化；被 size 覆盖攻击
  （如 0x4141414141414141）撑出的天文行数有 4096 行扫描上限，其余折叠显示。
- **新增模板 `basic_overflow_paint`**（"A 向下覆盖 B：逐 +8 覆盖（PhysicalGrid）"）：
  alloc A/B 后 4 次 EDIT 各多写 8 字节，作为默认启动演示；契约测试锁定 7 步与覆盖 span。
- **引擎修复**：`engine._memory_regions_from_physical` 对 implicit unknown hole span 也做逐词切分，
  当 size 被覆盖成巨值时死循环（~2^63/8 次迭代）。现仅对有真实字节的 span 切词边界。
- **清晰度 / 不遮挡 / 地址紧贴（用户反馈第二轮）**：
  - canvas 按 `devicePixelRatio` 放大 backing store，高分屏（125%/150% 缩放）下文字锐利；
  - 地址 gutter（+0x00 prev_size / +0x08 size / +0x10 user …）在格子**之后**绘制、右对齐到
    模型左沿外 10px，永远不会被模型遮挡或裁切；
  - chunk 标题（Chunk A [0] · 地址 · 状态）改为网格**第一行右侧的外部标注**，不占垂直空间，
    相邻 chunk 网格因此严格首尾相接（laneGap=0）——A 的末字节行与 B 的 prev_size 行直接相接，
    地址相邻关系一眼可见；
  - size 损坏（如 0x4141…）撑出的虚拟行窗口以诚实标记收尾（"size 已损坏，仅渲染前 0x… 字节"），
    不再显示假的 `+0x10000` 尾行；单元格长值按宽度测省略号截断，行高增至 30px；
- **Binary 页三报告卡片（用户规格）**：横排保护 chips 与「CLI 工具」按钮行移除，改为
  checksec / file / ldd 三张竖列卡片（`.binary-reports` 网格）。checksec 逐行 `key: value`
  —— 绿=开启/found，红=未开启/无，黄=Partial。数据经新 RPC `binary_reports`
  （WSL 真实执行 checksec/file/ldd，按需拉取、按工作区缓存、可手动「重新检测」）；
  WSL checksec 缺失时回退本地 ELF 解析并标注来源，值域并集兼容
  pwntools 短语（Canary found / NX enabled）、checksec.sh（ON/OFF/NONE）与本地解析（ON/OFF/FULL/PARTIAL）。
- **Binary 报告卡规范化 + ldd 修复（用户反馈）**：file/ldd 从原文堆砌改为结构化行
  （file→文件/类型/架构/链接/interpreter/BuildID/Stripped/最低内核；ldd→lib ⇒ 路径 (地址) 逐行，
  not found 红色）；**ldd 路径 bug 修复**——此前把 Windows 路径直接塞给 WSL ldd
  （`./C:\...` No such file），现经 `to_wsl_path` 转换；非动态链接给出诚实归类。
- **堆网格行合并 + 对齐（用户反馈）**：prev_size/size 两行合并为一行两格
  （+0x00 header），全表统一 16 字节行，右缘完全对齐；每格标注自身物理范围。
- **左栏 EXP 常驻（用户反馈）**：操作画布时 EXP 编辑器固定在左栏顶部
  （44% 高度，与 EXP 页/调试页同一实例），下方才是 操作流程/学习·校正 页签。
- **chunk 身份色带（Qt 风格）**：每 chunk 顶部 6px 身份色带 + 彩色标题标注，
  同一 chunk 跨步骤颜色稳定；生命周期不再占用色相（由标题文本与覆盖着色表达）。
- **Semantic Round Trip（EXP ⇄ Heap 同一 Canonical IR，用户规格）**：
  - `heap_state`/学习响应带 `canonical_ops`：每个 operation 带来源 EXP 行、参数与物理效果
    （alloc→chunk 地址、edit→写了哪个 chunk 哪个字段+物理区间、free→bin 去向）——
    EXP 与 Heap 画布都是「操作模型 + 物理状态」的投影，不再有主从。
  - **Reverse Operation Solver**（`reverse_edit`）：画布物理写入 → 哪个存活 chunk 的 user 区
    能写到该地址（溢出越界为核心场景，有界窗口）→ offset = target − user_addr →
    p64/bytes 数据表达式 → 本题 EDIT helper（HelperContract 优先，三参/flat 两种形态自动
    选择）→ Canonical EDIT Operation + 本题 EXP 渲染行。
    实测：`edit(0, 0x88, p64(0x421))`（写入 B.size）。
  - **待应用步骤**：校正提交后左栏底部出现「原 EXP / 画布产生的操作（待应用）」卡，
    [写入 EXP]（python 行进编辑器）[仅用于推演]（Canonical op 追加进操作模型并重放）
    [丢弃]。
  - **左栏拆双视图**：`EXP 源代码`（与 EXP 页/调试页**同一 Monaco 实例**，mountExpEditor
    搬移节点）| `操作流程`（Canonical IR 列表 + chunk 生命周期 + 字段溯源，点行跳转步进）|
    `学习 · 校正`（规则 + episodes + 补丁）。画布**单击** chunk → 左栏显示 创建/修改/释放
    历史；**单击字段格** → 字段值溯源链（当前值 ← Operation #n ← 来源调用）。
  - 契约测试：反向求解 `edit(0, 0x88, p64(0x421))` + 推演后 B.size=0x420 + 溯源链
    alloc→cross_chunk_overwrite(0x421) + 历史 [alloc, write] 端到端断言。
- **Correction Learning Engine（可验证的本地自主学习，替换朴素 old/new 学习）**：
  - 新增 `features/heapviz/learning.py`：CorrectionEpisode（完整语义上下文：来源调用点/函数/
    operation、前后值、变更物理区间、typed fields、analyzer reasoning、候选与证据链、
    challenge/helper fingerprint、置信度、scope）+ Correction Intent Resolver
    （向上追踪：chunk 为什么长这样 → 来源 operation → 调用点实参绑定）。
  - 三类意图（可否决自动判定）：① semantic_contract —— 证据链
    USER_CORRECTION + STATIC_DATAFLOW + REQUEST2SIZE_MATCH（r2s⁻¹(修正值) 命中调用点实参
    ⇒ 形参角色重绑），学成 USER_CONFIRMED HelperContract（resolver 证据级最高，
    结构推断不可覆盖）→ 整题重分析（症状性观测补丁随之作废）；
    ② observed_state —— 程序内部写入（源码不可见）仅 PhysicalMemory 写 + 后缀重放，
    不碰契约；③ derivation_rule —— helper 体文本数据流确认后生成
    LearnedRule(target=EDIT.offset, evidence=[USER_CORRECTION, STATIC_DATAFLOW_TEXT])，
    分析后应用（显式 offset 永远优先）。置信度阶梯
    USER_CONFIRMED > CALIBRATED > STRUCTURAL > ALIAS > UNKNOWN，低不覆盖高。
  - 会话/场景持久化携带 episodes + helper_contracts；桥响应带 learning 全量信息；
    JS 弹学习结果对话框（候选证据链 + 学到了什么 + 影响范围），校正记录页渲染 episode。
  - 契约测试：①②③ 三条路径（含 r2s 匹配的端到端重算断言、模板场景不碰契约断言、
    EDIT.offset 规则应用断言）。
- **拖入 ELF 修复**：Electron 32+ 移除 `File.path`，改用 preload `webUtils.getPathForFile`；
  拖放升级为 document 级全局（任意页面可拖入）+ 全屏虚线遮罩反馈，取不到路径时日志给明确提示。
- 杂项：图例改为「覆盖 CoverageSpan ∩ Cell」；底部状态行移至画布右上避免与 TOP 卡重叠；
  模板下拉框与实际加载场景保持同步；bin 泳道右移避让右侧标题标注。

## 一、总览

| 区块 | v0.28 (Phase A) | v0.29 (Phase B) |
|---|---|---|
| 桥 RPC | 6 方法 | 30+ 方法（堆/ROP/IOFILE/fmt/syscall/调试/工作区） |
| 页面 | 欢迎/Binary/EXP | 概览/Binary/EXP(工具列)/Heap/ROP/调试/Format/Syscall/Stack/工具箱 共 10 页 |
| 终端 | 单实例 WSL bash | 多实例：项目 bash + 每次调试一个新 pwndbg-mogai 实例 |
| 堆演示 | 无 | 16 模板 + EXP 回放，全部经 `GlibcHeapEngine` 真实仿真；JS 物理引擎渲染 |
| 画布校正 | 无 | PhysicalMemory 用户观测写入 → 后缀回放 → 识别规则即时推断 |
| IO FILE | 无 | Heap 工作台内独立页（glibc 布局 + 约束校验 + AST 证据） |
| ROPgadget | 无 | ROP 页真实执行（WSL）+ 收藏 Shelf + Chain/ret2libc/SROP + 终端直接可用 |

## 二、Python 真值层

- `pwnbao/electron_bridge.py`：全面扩容。新增 RPC：
  - 堆：`heap_templates` / `heap_load`（模板·场景·EXP 源码三入口）/ `heap_state` /
    `heap_correct` / `heap_undo_correction` / `heap_learn` / `heap_rule_toggle` /
    `heap_save` / `heap_open`
  - ROP：`cli_run`（ROPgadget/ropper/one_gadget/seccomp-tools/…注册表全量）/
    `gadget_shelf` / `gadget_search` / `rop_build` / `srop_plan` / `orw_plan` /
    `syscall_table` / `syscall_plan` / `cli_env_doctor`
  - libc/栈：`leak_derive` / `cyclic_pattern` / `cyclic_find` / `fmt_offset` / `fmt_plan`
  - 工具：`convert` / `blocks_list` / `command_templates` / `variable_set` /
    `workspace_save` / `workspace_open`
  - IOFILE：`iofile_layout` / `iofile_validate` / `iofile_analyze`
  - 调试：`pwndbg_status` / `pwndbg_ensure` / `debug_launch`（生成启动脚本，官方 pwndbg 零改动）
- `pwnbao/features/heapviz/bridge_session.py`（新增）：无头堆会话。
  `HeapSession` 持有 scenario+engine，`serialize_snapshot` 把每步回放状态
  （chunks/fields/regions/bins/handles/top/observations/intents/事件/scene groups/
  visual paint spans/physical relations）序列化为 JSON；校正走
  `CorrectionEngine.apply → rebuild_current_snapshot → replay_from_snapshot`
  的既有确定路径；`infer_rules_from_correction` + `merge_learned_rules`
  实现一次校正 → 场景级规则（第二次相同观测自动升级全局）。
- APP_VERSION → v0.29.0。

## 三、Electron 端（pwnbao-electron/）

- `main.js`：终端改为**实例制**（`terminal:start {cwd,kind,name}` / `terminal:kill`）；
  新增 `debug` 终端 kind——`wsl.exe --exec bash <launch.sh>` 直接进入 pwndbg-mogai
  （真实 PTY、ELF 预加载、x86 自动 starti、无引号转义风险）；
  `--shot` 扩为 6 页验收截图；桥超时放宽到 300s（容纳 pwndbg 首装）。
- `renderer/physics.js`（新增）：弹簧-质量物理引擎（半隐式欧拉、可调刚度/阻尼/锚点弹簧、
  体碰撞可关）。堆 chunk 之间**刻意不做刚体排斥**——物理重叠是利用语义事实，用颜色呈现。
- `renderer/heap.js`（新增）：堆工作台。
  - 每个模型（16 模板/自定义操作序列/EXP 识别结果）都由 Python 真实 allocator 仿真驱动，
    前端物理世界按步差分演化：新卡片弹入、bin 链弹簧重连、cross-write/overlap 着色。
  - 编辑画布：双击字段 → 校正对话框 → `heap_correct` → 后缀重放 + 学习规则；
    「撤销校正」「指认语义」「规则启停」齐备。
  - IO FILE 页：glibc 2.23–2.40 布局、字段编辑即时约束校验、EXP 的 FILE 写入 AST 证据。
- `renderer/pages.js`（新增）：Binary（CLI 工具真实执行）/ ROP（Gadget Explorer +
  Shelf + Chain Builder + ret2libc + SROP + 在终端运行 ROPgadget）/ 调试页 /
  Format（探针偏移 + 写入计划）/ Syscall（表 + ORW）/ Stack（cyclic + Leak→libc_base）/
  工具箱（编码转换 + 环境体检 + 命令模板）/ EXP 工具列（代码块占位符填充等 5 页签）。
- `renderer/app.js`：10 页壳、多终端面板（tab 切换/关闭/重开）、命令面板 18 条命令、
  对话框框架、EXP↔桥双向同步、`Ctrl+K`/`Ctrl+Shift+P` 双入口。
- `renderer/styles.css`：新增 heap/rop/iofile/dialog/term-tabs 等全部样式（VS Code Dark Modern 延续）。

## 四、验收

- 桥契约测试 `tests/test_v029_electron_bridge_v2.py`：14 项（堆回放/校正学习/IOFILE/
  fmt/cyclic/convert/leak/syscall/srop + 15 模板全量回放），与 `test_v028` 合计 18 通过。
- Electron smoke（bridge.ping / terminal.start / terminal.bytes）OK。
- 截图验收 `artifacts/ui_audit_v030/01–06`（欢迎/Binary/Heap/ROP/调试/命令面板），
  视觉门通过：堆画布为 PhysicalGrid 固定 cell 方格（格内打印物理范围）、B 的
  prev_size/size/user cell 内红色斜线覆盖、行结构全程不变、损坏 size 值 0x4141… 真实呈现。

## 五、遗留（下一阶段）

- 🔶 pwndbg 运行时快照（OSC machine protocol）与 Heap 页 RUNTIME 源联动
- 🔶 Monaco gutter 操作标记（§56 定位）在 Electron 前端的接入
- 🔶 场景时间线 override（校正该步/拆分/合并）的完整 UI
- 🔶 PyQt gui/ 保留为参考实现不再启动；`run_pwnbao.py` 入口默认仍指向 PyQt（可后续切换/删除）
