# v0.23.0

v2 提示词开源组件路线第一梯队落地（§2.1/§2.3/§18/§19/§20）。

## Qt ADS Dock（§2.1/§13）——探测式可选后端

- 新增 `gui/shell/editor_dock_area.py`：`DockEditorArea` 以 Qt Advanced Docking System 实现 EditorArea 同款契约（open_tab/focus_key/current_key/count/pin），central area 多 Dock 自动成 tab、可拖动分屏/浮动/持久化。
- `create_editor_area()` 工厂：`shell/docking=ads` 强制启用；`auto` 下可导入即 ADS，导入失败（PyQtAds 轮子与 PyQt5 二进制强相关）或 `=tabs` 静默回退 QTabWidget 版——**绝不带病运行**。
- 本环境 PyQtAds 4.2.1/3.8.1 均 DLL 拒载（与 venv 的 PyQt5 构建不匹配），故仓库默认路径保持 tabs；用户环境可 `pip install PyQtAds` 后设 `shell/docking=ads` 启用。
- ADS 默认皮肤由 Dark QSS + 暗 Palette 覆盖（§13 精修随 Dock 真机可用后细化）。

## Monaco EXP 编辑器（§2.3/§17）——可选前端

- **离线资产**：`pwncraft/gui/editor/assets/monaco/vs/`（loader/editor.main.js/css/workerMain，0.45.0，jsdelivr 落盘共约 3.9MB，零 CDN）。
- 新增 `gui/editor/monaco_editor.py`：QWebEngine + QWebChannel 桥；`pwncraft-dark` Monaco 主题（背景/选区/行高亮/行号/光标与 Workbench token 一致，§17）；worker 在 file:// 下不可用 → 主线程同步退化（编辑/高亮不受影响）。
- **文本镜像**：Legacy CodeEditor 始终存在并作为文本真值（PythonHighlighter/拖放/光标系能力全保留），Monaco 作为可见编辑面双向同步（防抖 setValue + contentChanged 镜像，`_syncing` 防回环）。
- 启用条件：设置 `editor/backend=monaco` 且非离屏会话；默认 `legacy`。拖拽代码块/ELF 为 Legacy 专属（如实限制）。
- `build.py` 打包 `gui/editor/assets`。

## 验证

- 全量回归：**388 passed, 4 skipped**；py_compile 通过。
- `THIRD_PARTY_NOTICES.md` 更新（Monaco 0.45.0 MIT 已捆绑；ADS 标记探测式可选后端）。

## 现存限制

- ADS 后端需用户环境自行 `pip install PyQtAds`（本 venv 轮子不兼容未默认启用）；ADS 精细皮肤（Dock 标题栏/浮动窗）待真机启用后按 token 精修。
- Monaco 下无 OperationMarkerGutter/PythonHighlighter（Monaco 自带高亮/撤销）；EXP↔Heap 源码定位（§56）在 Monaco 下暂缺。
- 拖拽代码块到 Monaco 页不可用（可从侧栏按钮插入）。
