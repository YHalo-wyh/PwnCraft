# pwncraft v0.5.1 更新日志

## UI

- 参考 AstrBot WebUI 的浅色工作台，改为白色圆角卡片、低对比边界、单一蓝色主按钮和更紧凑的表单层级。
- 精简侧边栏品牌区和 Tab 标题，五个工具页不再出现标题被截断/翻页箭头。
- HeapViz 顶部改为两行工具卡，工作模式、模拟模式、heap base 与场景操作不再挤成一行。
- 左侧控制 Tab 精简为“操作/画布层/路线/时间线/细节”，降低对右侧可视化宽度的挤压。

## Heap 画布

- 移除画布内重复的 step/chunks/handles/focus banner，状态统一由画布上方的状态条展示。
- 修复文字过长时的“水平缩放”漂移：现在只缩小到可读下限，再用真实省略号裁切，完整内容留在 tooltip/细节面板。
- 修复空快照仍保留上一步 heap 轴刻度的漂移 bug。
- heap 地址轴缩窄并统一显示 `heap base + offset`；具体 base 不再导致轴上全是巨大绝对地址。
- 非堆分配/伪造目标独立绘制在 `target / non-heap` 区，避免 libc/stack/target 符号混入 heap 轴导致排序错乱。
- 修复 consolidate 后 `top-merged/coalesced-alias` 未被识别为 `merged` 组的展示错误。

## 演示/路线

- 新增“chunk 地址与 header 布局”、“tcache 入链顺序”两个严格状态入门演示。
- 路线列表实时显示 `✓ supported / ? conditional / ✗ unsupported`。
- 严格模式禁止加载与当前 glibc 硬性不兼容的模板；推演模式仍可作为教学思路图查看。

## 验证

- 回归测试扩展到 45 项，新增入门演示最终状态、非堆目标分区、文字不压缩和空快照轴清理检查。


## 严格语义与代码识别补充

- HeapViz 默认固定为“进阶 + 严格 glibc”，移除模式切换和重复复制/缩放按钮，仅保留高频场景操作与一个“适应画布”。
- EXP 解析器会展开 `for i in range(...)`，并保留每次 add 的真实参数、菜单索引和 A/B/C… chunk 映射。
- 识别 `data = show(7)` 以及依赖该返回值的后续赋值；例如 `heap = u64(data[:5].ljust(8, b'\x00')) << 12` 会形成独立 value-flow 步骤并与代码选区同步。
- show 快照展示读取来源、user pointer、可证明的字节布局和派生结果；无法证明的运行时字节明确标为 unknown，不伪造数值。
- 修正 safe-linking 的 NULL 链尾：真实存储值为 `PROTECT_PTR(fd_pos, NULL)`，同时显示现代 glibc tcache 的第二机器字 `tcache_key`。
- unsorted/smallbin/largebin 改为横向 `bk | chunk | fd` 节点；fd 在上方前向弧线，bk 在下方反向弧线，arena sentinel 展开成左右两个端点。
- value flow、bin 链和 heap chunk 改为单列从上到下排列，避免窄视口中右侧内容被截断；chunk 的 `...` 使用真实几何居中。
