# v0.22.0

UI Theme 大改（按《Pwn宝 UI Theme 大改提示词》）：**Dark Workbench**。只改 Theme/Typography/Spacing/Widget Style/交互反馈/视觉层级；Heap Truth、PhysicalMemory、Analyzer、TargetContext、pwndbg-mogai、Runtime Bridge、EXP 语义**零改动**。

## Theme 架构（§32）

- `pwnbao/gui/theme.py` 单文件升级为 **`pwnbao/gui/theme/` 包**：
  - `tokens.py`：Design Token 单一来源（§2 色板：App #17181C / Sidebar #1C1D22 / Panel #202127 / Raised #25262D / Hover #2A2C33 / Active #30323A / Border subtle-strong / Text 四级 / Accent #7C74F2 三态 / Success/Warning/Error/Info；spacing scale 4/8/12/16/24；radius 6/8）。旧 `Colors` 属性名全部映射到暗色 token，存量 QSS 自动换肤。
  - `dark.py`：`build_stylesheet()` 全量 Dark QSS。
  - `widgets.py` / `icons.py`：Widget variant 词表与图标系统占位（§6：上线前必须统一线性 SVG，禁 emoji/PNG/Qt 默认图标）。
- 旧导入路径 `from pwnbao.gui.theme import Colors, build_stylesheet, FIXED_UI_SCALE` 完全兼容；scale 不变性测试继续通过。

## 全局暗色要点

- **表面层级（§3）**：靠明暗 + 1px subtle border 区分，无阴影；仅 Palette/Menu/Popover 允许 8px 圆角。
- **按钮（§5）**：IDE 平面控件（raised → hover 亮 → pressed 下压），Primary=Accent 只留给 Run/Apply/Save；Danger 默认中性、hover 才红。
- **输入（§14）**：#1A1B20 底、focus Accent 边、readOnly 虚线边框。
- **Tabs（§11）**：34px 高、无圆角、Active=亮字+2px Accent 下划线；Activity Bar（§7）：Activity 底色更深、选中左侧 2px Accent 指示条。
- **滚动条（§26）**：8px、低透明、hover 明显。
- **终端（§17）**：外围与 Workbench 统一暗色，内部保持 pwndbg 原生配色，不再出现米白 UI + 黑终端割裂。
- **Heap 画布（§18–§20）**：场景底 #18191E；Chunk 卡 = 深色 Surface + 低饱和 Identity Tint + 1px Identity Border（8 色 palette 全部换暗色映射，golden-angle fallback 同步变暗）；overlap 橙/cross-write 红橙按真实 byte span 着色；行分隔线 1px subtle。
- **清除了 115 处散落的纸色硬编码**（main_window 20 / heap_panel 46 / heap_canvas 46+ / workbench_panels 3），并把巨型页标题（21/18px）收敛到 §24 字号规范。
- Status Bar（§16）样式就位；Command Palette / Context Menu 暗色统一（§22/§29）。

## 验证

- 全量回归：**388 passed, 4 skipped**；`build_stylesheet` scale 不变性保持。
- 离屏截图：`artifacts/ui_audit_v022/01–05.png`（Shell 全页）+ `06_heap_dark.png`（Heap 暗色画布：深底 chunk/行分隔/accent 按钮）。
- 官方 pwndbg 未修改；核心逻辑零改动（§36）。

## 人工验收待办（§37，无法离屏覆盖）

- 125/150/200% DPI 下按钮/Tab 无裁字（token 已全部 px() 化，理论安全）。
- 中文 IME 输入、真彩终端、hover/pressed 手感。
- 仍存在的视觉问题：TaskProfileDialog 内部还有少量旧浅色片段（Phase F 清理对象）；heap 侧栏个别 tertiary 文字对比度待真机微调。
