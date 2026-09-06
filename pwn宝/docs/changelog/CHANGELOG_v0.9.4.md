# v0.9.4

## 画布文本完整性

- 移除 HeapAddressRail 和 Heap/Bin/Show scene 中的 `QFontMetrics.elidedText` 路径。
- `copy-overlapped`、`copy-overflow`、consolidated/fake/stale role、chunk/bin ID、symbolic expression 不再出现为带 `…` 的截断文本。
- 局部 cell 宽度不足时，字号逐级降低到 7pt；仍容纳不下时完整保留文本，交给 scene bounds/滚动条处理。
- Chunk role 移到 chunk header 第二行，可使用中间大部分宽度；`idx` 和 `size` 仍保持在右侧独立列。
- 新增 copy-overflow 真实 snapshot GUI 回归，确认两个 `copy-overlapped` 都完整显示，并且 scene 中没有 Unicode/ASCII 截断省略号。
