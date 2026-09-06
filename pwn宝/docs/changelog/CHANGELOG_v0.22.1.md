# v0.22.1

用户反馈两项修复 + 开源组件路线建档（参考《ZCode 式 UI 主题 v2 提示词》）。

## ① 按钮 / 菜单文字全量显示（§23/§25）

- **Tab 不再等分裁字**：`UiMetrics.harden_tab_bars` 从 `Expanding=True`（均分宽度，多 tab 时出现 "…ary" 半截）改为 **内容宽度 + 溢出滚动箭头**（VS Code 同款行为）；ElideNone 保持。
- **QComboBox 自适应内容宽**：`AdjustToContents + MinimumContentsLength(4)` 全局套用，任何下拉框不再裁字。
- **Activity Bar 宽度按字体度量**：`setFixedWidth(88)` 改为「最长英文标签 fontMetrics + 28px 指示条/内边距」，任意 DPI 下 "Exploit"/"Memory" 完整显示。
- 长 tab 标题 `pwndbg-mogai` → `pwndbg`（Debug 状态另有状态行说明）。
- 复查全 GUI `setFixedWidth/Height`：剩余两处均为地址轴数字列（UiMetrics 派生宽），无文本按钮违例。

## ② Heap EXP 导航黄线重构（§6）

**定位**：黄线 = `HeapExpEditor.paintEvent` 里横穿整个编辑器的 `#FBBF24` 1.8px 水平线（当前操作标记），配套 `OperationMarkerGutter` 的深蓝底 `#0B1220` + 琥珀琥珀色手柄（旧浅色残留）。

**替换（§6.2/§6.3）**：
- 编辑器内横穿黄线 **删除**，改为当前行左缘 **3px Accent 竖标记**（#7C74F2，仅 14px 高，随行滚动）。
- Gutter 改为 Workbench 暗色车道（#1C1D22 + 右缘 1px #30323A），标记 = **2px×18px Accent 圆角竖条** + 三条次级拖动线（#A4A7B0）；拖拽改 checkpoint 的交互完整保留。
- 画布空闲状态无任何横穿线（§21 heap_idle 达成）；Yellow 语义从「普通定位」退役，仅 Warning 可用（§7）。

## ③ 开源组件路线建档

- `THIRD_PARTY_NOTICES.md`：已捆绑资产（xterm.js 5.3.0 / addon-fit 0.10.0，MIT，本地落盘零 CDN）与 Python 依赖许可证清单；Qt ADS / Monaco / PyQtDarkTheme / Tabler-Lucide 列为规划项，落地时强制补录版本+许可证。
- 说明：Qt ADS Dock 与 Monaco 属 EditorArea 级迁移，作为 v0.23 独立轮次执行（本轮先保证显示完整性与黄线替换两条用户硬需求）。

## 验证

- 全量回归：**388 passed, 4 skipped**。
- 截图：`artifacts/ui_audit_v022/07_exp_no_yellow.png`（EXP 区无横穿黄线；gutter=暗车道+Accent 标记）。
