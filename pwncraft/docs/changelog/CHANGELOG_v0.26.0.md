# v0.26.0

UI 重构首轮收口（按《UI 重构首轮任务提示词》§8–§9）+ 启动崩溃修复。

## 修复：真机启动崩溃（用户报告）

- 根因：v0.23 引入 Monaco 时 `_on_load_finished` 方法缺失（清理残留），`loadFinished` 信号连接即 AttributeError。
- 修复：补齐该方法（ready 置位 + pending 文本回灌 + 加载失败标记）；真机探针验证 MainWindow 构造成功、Monaco 页正常创建（`exp_surface` index=1）。
- 附带：Monaco/xterm 的 WebEngine import 从模块顶层延迟到构造期——纯 Qt 测试进程不再被 AA_ShareOpenGLContexts 时序破坏。
- AA 标志确认在 `run_pwncraft.py` 首行（任何 QApplication 之前）。

## 验收测试（§8）

- 新增 `tests/test_ui_migration.py`（11 项）：
  - Theme import / token 抽查 / scale 不变性
  - Target propagation（import_target → workspace.binary → profile 全链）
  - Workbench open/close（opt-in，`PWNCRAFT_SHELL_GUI_TESTS=1`）
  - Yellow-line absence：源码无琥珀残留 + marker 为 3px Accent 竖条 + 全宽 drawLine 已删除
  - 前端抽象：TerminalFrontend offscreen 回退、Monaco 资产捆绑、Dock 后端选择、去重路径只读
- 说明（§8 如实声明）：offscreen 环境下 QtWebEngine 无法安全初始化，WebEngine 实渲染路径由真机探针验证（已通过）；像素级截图不在本轮。

## UI_MIGRATION_PLAN.md（§1/§9）

- Audit 摘要、组件清单（版本/许可证）、兼容风险与对策、实际执行顺序、遗留项——已归档于项目根。

## 验证

- 全量回归：**388 passed, 4 skipped** + 新增 11 项验收测试（10 passed / 1 opt-in skipped）。
