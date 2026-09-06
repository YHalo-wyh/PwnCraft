# CHANGELOG v0.30.1 — PyQt 版退役删除

> 日期：2026-08-29。上一版本 v0.30.0（PwnCraft 品牌 + 多 ELF 工作区 + checksec 竖排卡）。
> 按用户决定，PyQt 桌面版整体退役删除，Electron Workbench 成为**唯一主程序**。

## 一、删除清单

- `pwncraft/gui/`（52 个 .py，6.3MB）：ZCode 式外壳、HeapPanel、pwndbg_bridge、编辑器/终端前端、主题等全部 PyQt UI。
- 入口与打包：`pwncraft/main.py`（`python -m pwncraft`）、`run_pwncraft.py`、`build.py`（PyInstaller → exe）、`probe_v027_bottom_terminal.py`。
- PyQt 依赖的工具脚本：`pwncraft/tools/{performance_audit_v013, ui_audit_v012, ui_audit_v013, ui_capture_v020}.py`
  （`heap_ai_*` / `heap_semantic_benchmark` / `sunshine_ast_corpus` / `v012_benchmarks` 等无 Qt 工具保留）。
- GUI 测试 12 个文件 + 导航探针 `tests/_v015_nav_probe.py`；`tests/test_v020_shell.py` 重建为纯 core 版
  （保留 TargetContextTests 四项：导入副本 / libc 自动发现 / workspace target 往返 / schema=1 兼容）。
- **core 层孤儿模块**（删前逐一确认零消费方）：`core/ui/`（6 文件）、`core/preferences.py`（ExpPreferences）、
  `core/terminal/{wsl_pty,transport}.py`（Qt 传输层；`core/terminal/__init__.py` 修剪为 PyQt-free 导出，
  `pty_relay.py` 保留——`tools/pwndbg_interactive_performance.py` 仍以子进程方式使用）。
- `pwncraft/assets/`（HarmonyOS 字体，仅供 PyQt 字体解析）。

**归档**：以上全部内容在删除前打包至 `artifacts/attic/pyqt_v0.30.1.zip`（100 文件，zipfile 校验通过）。

## 二、依赖收敛

- `requirements.txt` → 仅 `pypdf>=6.0.0`（AI 语料工具用；Electron 真值桥为纯标准库）。
- `THIRD_PARTY_NOTICES.md` 移除 PyQt5 / PyQtWebEngine / PyQtAds / PyQtDarkTheme / pyte / PyInstaller 条目。
- Electron 侧组件清单（Electron / node-pty / Monaco / xterm.js / Lucide）不变。

## 三、文档与版本

- README：版本头 v0.30.1；目录结构树去除 gui/入口/打包条目；「运行」改为 `cd pwncraft-electron && npm start`；
  打包段如实说明 Electron 打包链（electron-builder）尚未引入。
- `APP_VERSION = v0.30.1`、`package.json 0.30.1`、状态栏字符串同步。

## 四、验证

- 全树 `PyQt5|PyQtAds|qdarktheme|QtWebEngine|QApplication` 引用清零；`compileall(pwncraft)` 通过。
- 存留 23 个测试文件分片跑（offscreen，每文件独立进程）全绿。
- `npm run smoke`（bridge.ping v0.30.1 / terminal.start / terminal.bytes）OK。
- `python -c "import pwncraft.electron_bridge"` 无 Qt 依赖，正常导入。
