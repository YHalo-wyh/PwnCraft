# v0.24.0

v2 提示词开源组件路线正式落地（§2/§20/§22）：**组件为主路径，QSS/QPainter 手搓降级为回退**。

## 开源组件栈（§2/§3/§20）

| 组件 | 职责 | 状态 |
|---|---|---|
| Qt Advanced Docking System（PyQtAds） | EditorArea：Dock / 拆分 / 浮动 / Tab（§2.1） | ✅ 默认后端（可导入时）；QTabWidget 为回退 |
| Monaco Editor 0.45.0 | EXP 源码编辑器（§2.3） | ✅ 默认前端（真实会话）；CodeEditor 为镜像真值 + 回退 |
| xterm.js 5.3.0 | pwndbg-mogai 终端面（§2.2，v0.20 起） | ✅ 默认；Legacy QPainter 为回退 |
| PyQtDarkTheme / qdarktheme 2.1.0 | Qt 基础暗色 Palette/QSS 基底（§2.4） | ✅ 引入，其上叠加 PwnCraft Design Tokens |
| Tabler Icons 3.31.0（outline 子集） | 统一 SVG 图标（§2.5/§6） | ✅ Activity Bar 六枚已接（muted 色，currentColor 换色渲染） |

**数据流边界不变（§20）**：ADS=工作区、Monaco=EXP 源码、xterm=终端、qdarktheme=基 Palette、Tabler=图标；Physical Heap Canvas 仍为自研 QGraphicsScene（PwnCraft独有核心）。

## 关键实现

- **PyQtAds DLL 修复**：PyQtAds 二进制链接的 Qt5 DLL 位于 `PyQt5/Qt5/bin`，默认不在搜索路径。新增 `pwncraft/gui/_qt_ads.py` 统一注册 `add_dll_directory` 后再导入（此前"找不到指定模块"即此根因）；全项目经该入口使用 ADS。
- `create_editor_area()` 工厂：`shell/docking`（auto/ads/tabs），默认 auto→ADS；`DockEditorArea` 与 QTabWidget 版同契约（open_tab/focus_key/current_key/count/pin），`main_window` 零业务改动。
- **Monaco 默认前端**（真实会话）：`editor/backend` 默认 `auto`→monaco；`pwncraft-dark` 主题（背景/选区/行高亮/行号/光标对齐 token）；文件协议下 worker 退化为主线程同步（编辑/高亮不受影响）。Legacy CodeEditor 始终存在并作为文本镜像真值（高亮/拖放/光标系能力保留），`editor/backend=legacy` 随时回退。
- **Tabler 图标系统**：`theme/icons.py` 按 (name,color) 缓存渲染（currentColor→指定色，2x HiDPI）；Activity Bar 六枚 outline 图标（muted 色）+ 原 zh/en 文字。
- **qdarktheme 基底**：`qdarktheme.setup_theme("dark") + PwnCraft QSS` 叠加（后写入者优先），两处 setStyleSheet 统一。
- **Status Bar（§16）**：`pwn · amd64 · libc … · pwndbg-mogai` 随 target_changed 更新。

## 验证

- 全量回归（offscreen，ADS Dock 后端下运行）：**388 passed, 4 skipped**。
- 导航探针 NAV PROBE PASS（11 目的地/单例/面板路由）。
- `THIRD_PARTY_NOTICES.md` 完整记录版本/来源/许可证（§19）。

## 现存限制

- PyQtAds 轮子与 PyQt5 构建强相关：本开发 venv 曾出现 DLL 拒载（`Qt5/bin` 注册修复后导入成功；若用户环境仍失败，自动回退 tabs 并在日志说明）。
- ADS 精细皮肤（Dock 标题栏/浮动窗/Auto-Hide）用默认暗色，token 级精修待真机。
- Monaco：无 gutter 操作标记（后续 decoration 方式回归）、拖代码块不可用、EXP↔Heap 源码定位（§56）暂缺。
- Phase F 剩余：task_profile 全删、FILE Typed View。
- DPI 人工验收（§23）：100/125/150/200% 截图待真机。
