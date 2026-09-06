# THIRD_PARTY_NOTICES

PwnCraft 发行包内捆绑/依赖的第三方组件、版本、来源与许可证（§19）。

> 当前发行包不包含旧桌面栈；PyQt5 / PyQtWebEngine / PyQtAds / PyQtDarkTheme / pyte / PyInstaller 不再是本项目依赖。

## Electron Workbench（`pwncraft-electron/`，npm 本地打包，运行时离线）

| 组件 | 版本 | 来源 | 许可证 | 用途 |
|---|---|---|---|---|
| Electron | 33.x | npm（npmmirror 镜像） | MIT | 桌面壳 / 窗口 / 主进程 |
| node-pty | 1.0.0 | npm | MIT | WSL bash 真 PTY（VS Code 终端同款组件） |
| Monaco Editor | 0.52.x | npm `monaco-editor`（min/vs 本地加载） | MIT | EXP 源码编辑器（file:// + blob worker，离线） |
| @xterm/xterm | 5.5.0 | npm | MIT | 底部终端渲染面 |
| @xterm/addon-fit | 0.10.0 | npm | MIT | 终端 fit → PTY winsize |
| Lucide Icons | 0.462.x（子集内联 SVG path） | npm `lucide-static` | ISC | 活动栏 / 按钮 / 命令面板图标 |

安装/构建期经 npmmirror 拉取；应用运行时不发起任何网络请求（无 CDN、无在线字体）。

## Python 运行时依赖（Electron 真值桥 `pwncraft.electron_bridge`）

| 包 | 许可证 | 用途 |
|---|---|---|
| pypdf | BSD-3-Clause | WriteUp PDF 语料解析（AI 语料工具） |

## 约定

- 所有前端资产（JS/CSS/SVG）随应用本地打包；禁止 CDN、npm 运行时下载、在线字体与在线图标。
- 升级任何组件时同步更新本文件的版本与许可证列。
