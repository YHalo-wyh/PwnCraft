# pwncraft v0.10.1

## Overlap presentation

- 删除 full-cover 场景右下角“覆盖”标记。
- 为每个 logical chunk 分配稳定、低饱和的独立颜色；生命周期变化不再改变 chunk 身份色。
- 新增物理 ownership map：按实际地址边界切段，单 owner 段使用 chunk 色，多 owner 段使用独立 clay overlap 色并直接写出完整 owner 列表。
- 重叠 alias 不再堆叠成多张重复的 PhysicalMemory 卡；物理 union 只绘制一次，所有 logical view 通过完整色签和 tooltip 保留。

## UI

- 全局切换为 MESH 风格的 paper/ink/khaki/clay/sage/mist 低饱和视觉语言。
- 按钮、输入框、页签、地址轴、字段行和 splitter 改为紧凑尺寸；操作表单默认完整露出。
- 默认三栏扩大 EXP 与物理堆，缩小 Bin/Show；普通场景自动 fit 宽高，减少上下滚动。
- 字段标题、provenance、value、meaning 分行布局，长 `allocator.metadata` 不再碰撞。

## Tests

- 新增 ownership 色、overlap 区间色、无覆盖按钮、默认零滚动回归测试。
- 更新固定逻辑密度与 full-cover 展示契约测试。
