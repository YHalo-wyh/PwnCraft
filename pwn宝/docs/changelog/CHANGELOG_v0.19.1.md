# v0.19.1

UI 修复：页签/导航文字截断 + 字体加粗（用户反馈）。

## 修复内容

- **页签文字不再截断**：此前只有 `AdaptiveTabWidget` 设置了 `ElideNone`，其余全部原生 `QTabWidget`（ROP 的 Gadget/Chain Builder/ret2libc、Stack 三页、Syscall 四子页、Libc 两页、Format 两页、Tools、Binary 符号表、HeapViz 内部页、WorkbenchDialog 等）走样式默认省略策略，出现 "Chain Builde"、"et2libc" 这类裁切。现在 `UiMetrics.apply_to()` 新增 `harden_tab_bars()`：对所有 QTabBar 统一 `ElideNone + Expanding + 允许滚动按钮`，一处策略全应用继承。
- **字体加粗**：
  - 页签栏：bar 字体加粗（保证按粗体度量计算宽度防再次截断），配合主题样式 `QTabBar::tab` 字重提升为 700、水平内边距 8→12，标签渲染完整且加粗。
  - 左侧主导航（Dashboard/Binary/…）：列表字体加粗；宽度从固定 132px 改为最小值模式，按粗体 sizeHint 自动增长（实测约 256px），"Dashboard" 等长名不再裁切。
  - 侧栏五个紧凑工具页签：保留紧凑字号但加粗。
- 明确不做的事：不加粗 QTabWidget 本体字体——那会级联到每个页面正文内容；只加粗页签栏与导航。

## 验证

- offscreen 实测：ROP/Syscall/WorkbenchDialog 页签 elide=ElideNone、bold=True；primaryNav 最小宽度自动升至 256 且加粗。
- 全量回归：**369 passed, 1 skipped**。
