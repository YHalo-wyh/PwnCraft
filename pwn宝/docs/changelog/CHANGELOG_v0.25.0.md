# v0.25.0

**Phase F 收尾** —— v0.20 大改（§99 A–F）全部完成；v2 提示词验收清单（§21–§23）除真机 DPI 外全部关账。

## task_profile 全删（§6/§97）

- 新增 `pwnbao/core/preferences.py`：`ExpPreferences`（io_name/architecture/libc_version —— 真正的用户习惯位）+ QSettings 持久化（`exp/preferences_json`）。
- `TaskProfileDialog` → **`ExpPreferencesDialog`**：只保留三项习惯设置；binary/libc 不再出现在偏好里（显式注明「来自 Target」）；`ok_button` 实时校验。
- `MainWindow`：
  - `task_profile` 降级为**派生别名**（`_profile_from_target()` = TargetContext + ExpPreferences，唯一真值；Phase F 完成后下一版移除别名本身）；
  - `_load/_save_task_profile`、`_apply_task_profile` 删除，替换为 `_refresh_placeholder_defaults()`；
  - 全部消费点（HEAP/IOFILE profile_provider、代码模板、块兼容过滤、snippet 改写）改读派生 profile；
  - 首次运行引导流程移除——空 Workspace 的 Import Page 就是引导（§23/§54），设置入口在「修改」按钮。
- 测试迁移：`test_heapviz_gui` 的引导对话框/onboarding 断言全部改写为新对话框与新偏好键。

## FILE = Typed View 归位（§50/§51/§84/§96）

- 盘点确认 IO FILE 工作区本就是 Typed View 语义（FileSnapshot 字段模型、backing range、字段编辑走 PhysicalMemory）；本轮将其入口正式定位于 **Memory 活动 → Libc/FILE tab**（v0.20 已完成导航迁移，本轮在文档与验收上关账），不再是任何一级工作区。高级 FILE 工具（_wide_data/vtable 等）仅在打开 FILE 检查页时出现（§52）。

## §56 Source ↔ Tool 双向定位

- `HeapPanel.locate_source_for_chunk(chunk_id)`：时间线操作（chunk/index/size → `add(0x60` 形态）与字段值两级候选在 EXP 源码中定位，命中即移动光标；未命中返回 -1 不闪跳。
- Chunk 右键菜单新增「在 EXP 源码中定位」→ `sourceLocateRequested` 信号 → 主窗口切 EXP tab 并执行定位。
- 反向（源码 → Heap）既有能力保留：选区绑定（TimelineCorrectionDialog）+ EXP 文本改动即重放。

## 验证

- 全量回归：**388 passed, 4 skipped**；py_compile 通过。
- §56 端到端：A/B 两 chunk 场景下 `locate_source_for_chunk` 命中 add 行。

## 现存限制

- `task_profile` 名称保留为派生别名（若干旧面板仍读），下一小版改完消费点后删除该属性本身。
- §56 的 Monaco 前端定位未接（Legacy EXP 面生效）。
- DPI/中文 IME 等真机人工验收项不变。
