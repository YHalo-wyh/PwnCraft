# v0.27.0

底部面板重构为 VS Code 式内置终端（§7 Bottom Panel: Terminal / Logs）。

## 底部 Dock：终端优先

- 底部面板从「日志标题 + 只读文本框」改为标签页 Dock：**终端**（默认）+ **日志 / 诊断**。
- 新增 `pwncraft/gui/terminal/shell_terminal.py`（`ShellTerminalPanel`）：
  - 复用调试器真 PTY 管线：`XtermFrontend`（xterm.js，离线资产）渲染 + `WslPtyTransport`（pty_relay.py）fork `bash --login -i`；legacy 前端照常自动回退。
  - 默认连接本地 WSL；首工作区显示时自动启动（offscreen 会话不自动 spawn，保持测试离线）。
- 原始 `log_box`（QPlainTextEdit 只读日志）退役；`log()` 只进结构化 LogsDiagnosticsPanel（类别/级别/筛选），时间戳由事件模型承载。

## 工作目录跟随项目（Single Workspace）

- `WslPtyTransport.start()` 新增 `cwd` 参数：`wsl.exe --cd <wsl_path> --exec ...`（与 `--exec` 组合验证过，Windows/WSL 路径均可）。
- 目录来源：`workspace.project["project_path"]`。跟随点：
  - ELF 导入完成（`_on_tool_finished`）→ 终端 cd 到 ELF 所在目录；
  - 概览页打开 `.pwncraft` 项目（`projectOpened`）→ cd 到项目文件所在目录；
  - `workspace_merged` 事件 → 同步跟随。
- 运行中的 shell 收到一行 `cd <shlex.quote(path)>`；未启动/已退出则记住目录，下次启动生效。若前台程序正在运行，注入文本会落入其 stdin——日志中如实说明。

## 交互

- `Ctrl+\`` 切换底部终端（显示/隐藏并聚焦），VS Code 习惯。
- 终端头部：项目目录（中段省略 + tooltip）+「启动/重启终端」按钮；底部状态行显示连接状态/退出码/失败原因。
- `closeEvent` 会同时停掉内置终端与 pwndbg 会话。

## 测试

- 新增 `tests/test_v027_bottom_terminal.py`（11 项）：offscreen 不自动 spawn、bash 启动参数与 `--cd` 路径、无项目时省略 `--cd`、运行中注入 cd / 同目录 no-op / 无效目录提示、BottomPanel 标签顺序与焦点切换、MainWindow 集成（日志路由 + 目录跟随）、transport cwd 兼容旧调用形态。
- 更新 `test_heapviz_gui.py` 中原 `log_box` 可见性断言为底部 Dock 标签结构断言。
- 全量回归：**409 passed, 5 skipped**。
- 真机探针 `probe_v027_bottom_terminal.py`（项目根，可重跑）：windows 平台实渲染路径验证通过——XtermFrontend 生效、WSL bash PTY 建立且有输出回流、底部 Dock 结构正确、`follow_project` 向运行中 shell 注入 cd 成功。

## 边界说明

- 未新增任何第三方组件（xterm.js 沿用既有离线资产），THIRD_PARTY_NOTICES 无变化。
- pwndbg 调试终端仍是 Debug 编辑器标签；内置 shell 与 pwndbg 会话互不混流（§57/§58 不变）。
- 已知限制：运行中的 shell 被注入 `cd` 时，若正在运行前台交互程序，该行会进入其 stdin（VS Code 新终端才继承 cwd 的同类权衡）。
