# PwnCraft v0.12 Offline Semantic Closure 迁移计划

> 本文件在 v0.12 功能代码变更前建立。它冻结 v0.11 现状、迁移边界、兼容策略和验收口径，后续实现不得以 UI 演示结果覆盖运行时/物理内存事实。

## 1. 基线冻结

- 当前产品基线：v0.11.0 Integrated Pwndbg Tutor Terminal。
- 当前自动化基线：`204 passed, 1 skipped`；Ruff 通过。
- 既有 60 项语义基准：`60/60`。
- Sunshine 当前原始语料统计：FULL 23、PARTIAL 18、MODEL_READY 2、PARSE_ONLY 9、SEMANTIC_VERIFIED 0；MODEL_READY-or-better 为 `43/52 (82.69%)`。
- Pwndbg 固定离线版本：`2026.07.29`。
- 已验证的 AArch64 静态安全会话修复必须保留：读取 ELF `e_machine`，仅 x86/i386 自动 `starti`，异构目标禁止错误架构运行；GDB 使用 `-nx` 并关闭 debuginfod。
- 物理堆真值基线：`PhysicalMemory`、分配器策略、bin/top/freelist 行为、历史快照和 Pwndbg OOB 通道均作为兼容边界，不在 v0.12 重写。

## 2. 不变量

1. 画布拖拽、缩放、对齐、折叠仅修改布局，绝不修改 chunk 地址、分配器状态或物理内存。
2. 新 chunk 对旧地址的正常复用不产生“重叠”色；只有当前物理事实中的跨界写入或损坏重叠才着色。
3. 不依靠 helper 名称、house 名称、历史发生过的 overwrite 或 UI 标签推断当前物理损坏。
4. `INVALID` 编辑必须拒绝；`REPRESENTABLE_CORRUPTION` 允许记录为观测到的损坏字节；不提供 Force Apply。
5. 未证明的语义保持 `UNKNOWN`，不得为提高覆盖率猜测。
6. 所有 v0.12 分析、修正和测试离线运行；不得访问 socket、requests、urllib 或 httpx 网络接口。
7. v0.11 Pwndbg 终端、ELF 拖入、patchelf 和架构保护继续回归，不用 v0.12 分析器重写调试器。

## 3. 保留、替换、兼容与删除

### 3.1 原样保留

- `heapviz/physical_memory.py` 的地址空间与写入真值语义。
- `heapviz/engine.py` 中已验证的 glibc 分配器状态迁移；只通过适配层接收 Canonical IR。
- Pwndbg PTY/OOB、会话管理、架构检测与实时校准底层。
- ELF 同目录 loader/libc 发现及可逆 patch 流程。
- v0.11 的 60 项语义基准及已有 allocator truth 测试。

### 3.2 逐步替换

- 名称驱动的单 helper 映射 → 多 helper 的 `HelperContractResolver`，名称只参与候选召回。
- 分散在 `HeapOperation.meta` 中的 offset/length/data → 一等 Canonical Operation 字段。
- Python 原生 int/bytes 与不透明字符串 → 可判别的 Concrete/Symbolic/Unknown 值域和长度表达式。
- 画布内部颜色启发式 → `HeapVisualModelBuilder -> PaintSpan[] -> Renderer`。
- 临时画布 override / Custom Chunk → 类型化 Correction Patch。
- Heap 页时间线、Before/After、校准展示 → 独立 Logs/Diagnostics 工作区。

### 3.3 兼容适配

- 保留 `HeapOperation` 公共接口，提供 Canonical IR 双向/单向适配，避免一次性重写 engine。
- 保留现有 `HeapApiProfile` 导入能力，并迁移为 imported contract source。
- 已存布局和老工程允许缺字段加载；缺失布局自动生成，旧手工覆盖不再作为语义真值。
- 既有测试中直接构造 operation/snapshot 的路径继续可用。

### 3.4 从 Heap 页删除

- Custom Chunk Overlay / 自定义 Chunk。
- Heap 页内的 Timeline Table、Current Step Detail、Before/After、AI correction、完整 live calibration 面板。
- chunk 卡片内部的小型修正/覆盖按钮与 `overlap` 文本徽标。
- 直接编辑 `bin_location` 字符串和任何 Force Apply 入口。
- 右侧重复的 bin 原始文本；只保留结构化 Bins/Info。

## 4. 目标模块

```text
pwncraft/heapviz/
  semantics/
    canonical_ir.py
    values.py
  contracts/
    model.py
    aliases.py
    body_flow.py
    wrapper_graph.py
    rules.py
    resolver.py
    persistence.py
  constraints/
    result.py
    engine.py
    chunk.py
    bins.py
    top.py
    freelist.py
    address.py
    policies.py
  corrections/
    model.py
    engine.py
    scope.py
    rebase.py
    rule_inference.py
    history.py
  presentation/
    layout.py
    visual_model.py
pwncraft/gui/logs/
  model.py
  panel.py
```

具体文件可按现有包结构合并，但公共类型、职责边界和依赖方向必须保持：解析/contract → Canonical IR → engine/constraints → snapshot → visual spans/layout → Qt renderer。

## 5. 分阶段迁移

### 阶段 A：Canonical IR 与值域

- 定义 ALLOC/FREE/EDIT/SHOW 的统一 operation，EDIT 显式拥有 target/offset/length/data，SHOW 显式拥有 offset/length。
- ALLOC 区分 `menu_request` 与 `allocator_request`。
- 实现 `ConcreteInt`、`SymbolicInt`、`ConcreteBytes`、`SymbolicBytes`、`LengthExpr`、`PointerExpr`、`Unknown`。
- 把 `len()`、拼接、重复、切片、对齐和 pack 结果长度纳入确定性代数。
- 为旧 `HeapOperation` 提供兼容转换并建立单测。

### 阶段 B：Helper Contract Resolver

- 支持同一种 kind 的多个 helper、实参重排、方法 helper、赋值别名、简单 `functools.partial`、wrapper 变换与循环/深度限制。
- 证据优先级固定为：USER_CONFIRMED > imported profile > inline annotation > structural body > wrapper > safe alias > name candidate > UNKNOWN。
- 函数名不直接证明语义；冲突时输出诊断和 UNKNOWN。
- contract 持久化包含 source/fingerprint/confidence/evidence，源 fingerprint 改变时标记 STALE。
- 修改 contract 后对所有受影响调用重新 lower，而不是改单个 operation。

### 阶段 C：约束与修正

- 统一 `VALID / REPRESENTABLE_CORRUPTION / INVALID / UNKNOWN`。
- 校验 size/alignment/minsize、PREV_INUSE/prev_size、safe-link 字段地址、bin 双向关系、top 边界。
- 定义 LayoutPatch、HelperContractPatch、ObservedMemoryPatch、StructuralViewPatch、AllocatorProfilePatch。
- 语义 patch 可重放；布局 patch 不改变语义。提供撤销/重做、冲突、stale 和 rebase 诊断。

### 阶段 D：视觉模型与自由布局

- 定义 `CanvasObjectLayout(object_id,x,y,width,height,collapsed,locked,z_order,group_id)` 并持久化。
- 支持拖拽、缩放、多选、框选、对齐、分布、锁定、复制布局、折叠、自动布局、物理布局、undo/redo。
- chunk 卡片内无按钮；单击选择，双击路由到左下 Context Editor。
- 使用当前 physical bytes/provenance 构建 BASE、CROSS_WRITE、PHYSICAL_OVERLAP、INVALID_MARK spans。
- 一个字节按元数据字段宽度的 1/8 绘制；仅实际受影响区间换色。
- 分类 ACTIVE_ALIAS/NORMAL_REUSE/STALE_VIEW/CORRUPTION_OVERLAP，只有 CORRUPTION_OVERLAP 着色。

### 阶段 E：UI 与日志工作区

- 1600×1000 保持左上 EXP、左下 Context Editor、中间 Heap Canvas、右侧 Bins/Info 三列。
- 调整默认 stretch、字体和卡片最小尺寸，使 1366/1600/1920 常用内容默认完整显示，避免文本省略和无必要纵向滚动。
- Heap 页只呈现当前真值与当前编辑上下文。
- 新建 Logs/Diagnostics 工作区，承载 Analyzer、Replay、Correction、Validation、Calibration 事件及筛选。
- Pwndbg 工作区维持现有终端交互，并通过事件总线与当前堆快照同步。

### 阶段 F：测试、文档与交付

- 现有全部测试及 60/60 语义基准回归。
- 新增 >=100 个 helper variant 确定性用例及 20–30 个 correction benchmark。
- 离线门禁 monkeypatch socket.connect、requests、urllib、httpx。
- Sunshine 同时报告 raw 和 static-eligible，static-eligible 目标 >=90%；未达标如实列出 UNKNOWN 原因。
- 生成 1366/1600/1920 UI 审计截图：normal、cross header overflow、partial byte overwrite、corruption overlap、normal reuse、edit validation、helper contract、free layout、logs、pwndbg regression。
- 新增架构文档：`OFFLINE_ANALYZER_ARCHITECTURE.md`、`HELPER_CONTRACTS.md`、`HEAP_CORRECTION_MODEL.md`、`HEAP_CANVAS_EDITING.md`、`LOGGING_ARCHITECTURE.md`。
- 输出 `VALIDATION_v0.12.0.md`、`CHANGELOG_v0.12.0.md` 并构建 Windows `dist/pwncraft.exe`。

## 6. 验收矩阵

| 维度 | 必须证明的结果 |
|---|---|
| Offline | 网络 API 全部封锁时导入、分析、修正、重放、UI 可用 |
| Resolver | 名称误导不误判；多 helper/重排/method/alias/partial/wrapper 可识别；冲突为 UNKNOWN |
| Canonical IR | add/edit/show/delete 变体归一；offset/length/data 不藏在 meta |
| Symbolic | `len(payload)` 和字节长度链可追踪；无法具体化时保留表达式 |
| Truth | INVALID 拒绝；可表示损坏不污染 allocator 推导；无 Force Apply |
| Color | 正常复用无色；只有真实跨界/损坏 byte span 换色；无 overlap 文本 |
| Layout | 拖拽/缩放/对齐/锁定/撤销重做不改变地址与物理内存 |
| Corrections | helper 修正泛化到该 helper 所有调用；fingerprint 变化 STALE |
| UI | Heap 页无旧时间线/AI/校准；Logs 独立；三种分辨率无关键截断 |
| Regression | Pwndbg、AArch64 static-safe、patchelf、60/60、allocator truth 全通过 |

## 7. 失败处理

- 若运行时与源码/缓存冲突，以实际运行、捕获流量、当前加载资产和进程配置依次为准。
- 若语料目标未达成，不引入基于名称的猜测；输出静态可判定分母、UNKNOWN 分类和复现样本。
- 若新 UI 影响物理真值，立即回退到 Canonical/engine 边界定位，不在 renderer 内补语义。
- 若 Pwndbg 回归失败，隔离调试器会话与 v0.12 日志总线，保留 v0.11 启动路径。

## 8. 最终交付清单

最终报告逐项给出：结果、关键证据、精确回放/验证步骤、本地产物路径、测试输入/期望/实际、覆盖指标、未满足约束与 UNKNOWN 清单。只有从干净基线可重复完成测试、截图和 EXE 构建后，v0.12 才算完成。
