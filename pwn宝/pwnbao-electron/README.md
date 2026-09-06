# pwn宝 Electron Workbench

当前唯一主程序：Electron + Monaco Editor + xterm.js/node-pty + Python 真值桥。

## 一键启动

在项目根目录双击：

- `启动新版.bat`

也可以右键 PowerShell 运行：

- `启动新版.ps1`

脚本会自动进入 `pwnbao-electron/`，首次缺少 Electron 依赖时执行 `npm install`，然后运行新版工作台。

## 手动启动

```bash
cd pwnbao-electron
npm install        # 首次或 node_modules 缺失时
npm start          # 完整应用
npm run smoke      # 无头冒烟：桥 ping + WSL 终端字节回流
```

要求：Windows 上可用 `node/npm/python`，WSL 可用；Python 桥通过 `pwnbao.electron_bridge` 复用本仓库真值层。

## 组件

| 层 | 组件 |
|---|---|
| 桌面壳 | Electron |
| EXP 编辑器 | Monaco Editor（本地 `min/vs`，无 CDN） |
| 终端 | xterm.js + node-pty → WSL bash / pwndbg-mogai |
| 图标 | Lucide（内联 SVG，currentColor） |
| 真值层 | `pwnbao.core` + `pwnbao.features`（stdio JSON-RPC 桥） |
