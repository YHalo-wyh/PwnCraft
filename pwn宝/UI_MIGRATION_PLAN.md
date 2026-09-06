# UI_MIGRATION_PLAN.md

> 状态：Electron Workbench 已成为唯一主程序。旧桌面栈、PyInstaller 构建产物和截图探针已从当前工作区移出。

## 当前产品形态

- 前端：`pwnbao-electron/`（Electron + Monaco + xterm.js + node-pty）。
- 真值层：`pwnbao/electron_bridge.py` 通过 stdio JSON-RPC 调用 `pwnbao.core` 与 `pwnbao.features`。
- 堆演示：`bridge_session.HeapSession` 真实 glibc allocator 仿真（PhysicalMemory 单一真值）→ JSON → JS 画布；画布校正实时回放并后台推断规则。
- 调试终端：`debug_launch` 生成 WSL 启动脚本，node-pty 新实例进入 `third_party/pwndbg-mogai`。
- IO FILE / ROP / Format / Syscall / Stack / 工具箱均在 Electron Workbench 内完成。

## 启动

优先使用项目根目录的一键脚本：

```text
启动新版.bat
启动新版.ps1
```

手动启动：

```bash
cd pwnbao-electron
npm install
npm start
```

## 清理约定

- 当前工作区不再保留旧桌面源码、旧打包 exe、旧 PyInstaller spec 和旧截图探针。
- 历史变更记录仍保留在 `docs/changelog/`，只作为版本审计资料，不作为当前入口或依赖来源。
- 第三方依赖以 `pwnbao-electron/package.json` 和 `requirements.txt` 为准。
