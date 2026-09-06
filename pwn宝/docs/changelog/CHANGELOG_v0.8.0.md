# v0.8.0 - Semantic Core + Canvas 2.0

## 语义核心

- 新增 Program Semantic IR：调用目标、receiver、源码区间、置信度和证据与 allocator event 分离。
- 新增类型化表达式，`p64(target ^ (pos >> 12))` 等 safe-linking 结构不再退化成普通字符串。
- 新增 Challenge Behavior Profile，一个 helper 可展开为 0/1/N 个 allocator effect，并支持内部 chunk 与 `bind_handle=false`。
- receiver-aware 识别排除 `dict.update`、`list.remove`、`set()`、`path.move`、`os.remove`、`shutil.copy` 和未知第三方对象方法，避免伪事件导致后续地址漂移。
- 本题行为模型优先于历史 learned rule；每个展开操作保留 helper、effect、源码行和证据。
- 行为模型 schema 改为严格校验：未知 effect、空函数名、重复参数、重复 helper 和错误根节点都会报告具体错误。

## Canvas 2.0

- Physical Heap、Bins/值流/外部目标使用独立固定列，bin 数量不再推动 heap 主列上下漂移。
- 默认主图只显示 chunk 名、idx、size 和 payload/next 摘要；完整 memory region 在详细模式、Inspector 和 tooltip 中查看。
- 真实 heap base 显示完整绝对地址与相对偏移；地址栏使用 `mapFromScene()` 跟随缩放和滚动。
- chunk 按物理地址连续排列，上方低地址、下方高地址；top chunk 与主列对齐。
- safe-linking 主图归约为 `next -> A/NULL`，完整 `PROTECT_PTR` 表达式留在详情证据中。
- scene model 与 snapshot diff 独立于 Qt renderer，按 `physical_id` 产生 create/update/move/delete 变化；timeline 使用轻量交叉过渡。
- 双击 chunk 只聚焦 Inspector，不修改 EXP；背景大网格已移除。

## 场景与界面

- 场景 schema 升级为 4，保存/加载 Challenge Behavior Profile。
- helper 映射导入导出包含行为模型；无效 JSON 禁止导出或保存旧模型冒充当前输入。
- 行为模型错误使用醒目状态文字提示，并保留上一次有效模型继续分析。
- Windows 原生 Qt 视觉基线：`artifacts/ui_audit/canvas_v08_windows_final.png`。
