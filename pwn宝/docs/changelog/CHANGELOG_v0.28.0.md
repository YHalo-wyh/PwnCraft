# v0.28.0

UI 迁移 Electron Phase A：VS Code 同款开源组件栈的新前端落地（`pwnbao-electron/`）。

## 新增：Electron Workbench（Phase A）

- 技术栈（全部 npm 本地打包，运行时零联网）：
  - **Electron** 桌面壳（contextIsolation + preload 白名单 IPC，渲染进程无 Node 权限）
  - **Monaco Editor**（VS Code 同款编辑器）承载 exp.py，file:// + blob worker 离线加载
  - **xterm.js + node-pty**（VS Code 同款终端栈）：`wsl.exe --cd <项目目录> --exec bash --login -i`
  - **Lucide Icons** 内联 SVG（currentColor）
  - Dark Modern 风格低饱和主题，贴近用户给出的 VS Code 欢迎页参考图
- **真值层不动**：新增 `pwnbao/electron_bridge.py`，Electron 通过 stdio 行式 JSON-RPC 调用
  既有 core（`import_target` + `auto_patch_elf` + `BinaryInspector` + `WslToolRunner` +
  `PwnWorkspace`）。UI 只消费 Truth，不制造第二套 Truth。
- Phase A 已迁移功能：
  - 欢迎导入主页重做：盾形 logo + 虚线拖放方框（拖拽/点击/回车均可）+ VS Code 式快捷键提示
    （Ctrl+Shift+P / Ctrl+O / Ctrl+`）+ 最近导入列表
  - Binary 概览页：保护 chips（PIE/NX/Canary/RELRO）、架构/入口/libc/interpreter 卡片、
    file/checksec/readelf 静态报告
  - EXP 编辑器（Monaco，Python 高亮；Monaco 缺失时自动回退纯文本框并如实记录日志）
  - 内置 WSL 终端：开机启动在 ~，导入 ELF 后自动重启到项目目录（`/mnt/...` 路径）
  - 结构化日志页（时间/级别/筛选/清空）、命令面板（Ctrl+Shift+P）、状态栏
  - 快捷键：Ctrl+O 导入、Ctrl+` 切终端、Ctrl+S 保存 EXP、Esc 关面板
- **零裁切**：全布局 flex 收放 + `[hidden]{display:none!important}` 兜底；标签页可横向滚动、
  按钮随文字撑开、长路径换行显示不截断；欢迎页内容超高时用 margin:auto 居中（不裁顶）。

## 过程中修掉的坑（记录给后续 Phase）

- node-pty 1.0 的 kill() 旧路径会用 `process.execPath` fork `conpty_console_list_agent`，
  在 Electron 主进程里变成拉起 electron.exe 而崩（AttachConsole failed）——spawn 传
  `useConptyDll: true` 走 DLL 路径规避。
- ConPTY 下 `wsl.exe --cd <Windows 路径>` 报 `Wsl/E_INVALIDARG`；必须先转成 `/mnt/...`
  （与 core.wsl.WslToolRunner.to_wsl_path 同一翻译）。
- CSS 作者样式的 display:flex 会覆盖 UA 的 `[hidden]`，导致所有页面/面板叠显——全局兜底规则已加。

## 运行方式

```bash
cd pwnbao-electron
npm install   # 首次（npmmirror）
npm start     # 完整应用；npm run smoke 冒烟；--shot 截图四界面
```

## 验证

- 新增 `tests/test_v028_electron_bridge.py`（4 项）：hello/ping 往返、未知方法干净报错、
  完整 import_target 流（工作副本/只读原始副本/architecture/project_path 传播）、非 ELF 拒绝。
- Electron 冒烟（`npm run smoke`）：bridge.ping / terminal.start(node-pty) / terminal.bytes 全绿。
- 真机截图（`artifacts/ui_audit_v028/01..04`）：欢迎导入页 / Binary 概览 / EXP 编辑 / 命令面板，
  逐一目检：无文字裁切、终端真实 bash 提示符且导入后切换到项目目录、Monaco 高亮正常、
  保护 chips 与静态报告如实渲染（本机 WSL 缺 checksec 时显示其真实报错）。
- Python 全量回归：见验证记录（新增 4 项桥测试）。

## 诚实边界

- Phase A 未迁移：Heap 画布、pwndbg 调试工作台、ROP/Syscall/Stack/Format、IO FILE、
  Workbench 对话框 —— 仍在 PyQt 版（`python run_pwnbao.py`）中按 Phase B/C 计划逐个搬入。
- 本机 WSL 未安装 checksec 时静态报告如实显示其错误行，不伪造输出。
