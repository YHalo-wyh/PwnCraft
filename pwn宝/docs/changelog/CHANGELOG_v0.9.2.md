# v0.9.2

## 独立 Bin / Show 证据区

- HeapViz 右侧改为 `PHYSICAL HEAP | BIN / SHOW` 内层 splitter，宽度可拖动。
- 主 `HeapCanvas` 只显示物理堆、地址轴、typed fields、top 和非堆目标，不再将 bin/show 堆到 chunk 列下方。
- 新增 `BinShowCanvas`，将 tcache/fastbin/unsorted/smallbin/largebin 结构与 show/value-flow 卡片统一放在画布右侧独立区域。
- 两个 scene 独立滚动；长 bin 链不再改变地址轴或 chunk 可见范围。
- 点击/双击 bin 节点会同步选中物理堆 chunk 和详情 inspector。
- 无 bin 或无 show 时在右侧保留明确空状态，避免误以为画布未加载。

## 回归

- UI 测试验证 show/value-flow 不再出现于物理堆 scene，而是与 tcache 一起出现在右侧证据 scene。
