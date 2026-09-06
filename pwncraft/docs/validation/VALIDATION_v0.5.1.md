# pwncraft v0.5.1 验证记录

## 自动化回归

Windows PyQt5 虚拟环境下执行：

```bat
set QT_QPA_PLATFORM=offscreen
python -m unittest -v tests/test_heapviz_core.py tests/test_heapviz_gui.py
```

结果：`Ran 48 tests ... OK`。

## 新增重点校验

- 入门 chunk 布局模板只产生 A/B/C 三个真实 allocator 状态，无凭空 bin/目标。
- tcache 入链模板最终链为 `C -> B -> A`。
- concrete heap base 在轴头显示，轴刻度仍保持 `+offset`，绝对地址保留于 tooltip 上下文。
- `target_addr` 类非堆 chunk 不会出现在 heap 轴，而是进入 `target / non-heap` 区。
- 画布文字 item 的 scale 恒为 `1.0`，长文本用 elide 而非水平压缩。
- 从有 chunk 快照切回 initial 后，地址轴上下文会立即清空。
- consolidate 后的 `top-merged/coalesced-alias` 会被标记为 merged 组。
- `for range`、`data=show(7)` 与 `u64(data[:5].ljust(...)) << 12` 会生成连续、可回放的 value flow。
- safe-linking 的 NULL next 按 `PROTECT_PTR(pos, NULL)` 建模，数值 heap base 下能严格还原 heap page。
- 双链 bin 使用分栏节点与上下两条 Bézier 曲线，chunk 省略号按卡片中心对齐。

## 可视检查

- 1600x1000 下侧边栏五个工具 Tab 可同时显示，无翻页箭头。
- 代码块树改为单列，说明转入 tooltip，无水平滚动条。
- HeapViz 顶部控件分成设置/场景两行，无按钮相互挤压。
- 画布内无重复 step banner，chunk header、字段表和 non-heap 卡片无文字交叉。
- 默认界面是进阶模式、allocator 是严格模式；模式下拉、复制语义段与 +/- 缩放按钮不再占用工具栏。
