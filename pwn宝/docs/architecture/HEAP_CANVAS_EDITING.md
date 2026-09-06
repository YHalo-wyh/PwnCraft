# v0.13.2 Physical Heap Canvas

## Chunk 是不可移动的物理锚点

已有 Chunk 按物理地址顺序排列，不提供上下/左右拖动、角点缩放、对齐或自由布局。编辑模式选中 Chunk 后只显示上、下两个纵向覆盖边手柄。

- 下边向下拉：该 Chunk 是 overflow 覆盖主体。
- 上边向上拉：该 Chunk 是 underflow 覆盖主体。
- 反向拖回：只缩短已创建的覆盖延伸，不会缩小原 Chunk。

拖边不修改 Chunk 本体的 `address/chunksize`，而是建立由该 Chunk 拥有的越界写区间。这符合真实 heap overflow/underflow：源 allocation 大小不会因越界写自动变大。

## 覆盖主体与受体

手柄所属 Chunk 始终是覆盖主体。延伸范围与其他 Chunk 相交时：

- 只对真实相交物理范围换成 overlap 色。
- 被覆盖 Chunk 的名称/header 行同步换色，但名称保持可见。
- 原 Chunk 卡片的位置、大小和物理地址不变。

## 覆盖内容默认为空

手动延伸只证明“这些地址将由主体写入”，不猜测 payload，因此区域显示为“覆盖内容：空”。点击区域后才打开 Inline Editor；提交路径为：

```text
Overflow Inline Editor -> ConstraintEngine
 -> PhysicalMemory.write(CROSS_CHUNK_OVERWRITE provenance)
 -> rebuild_current_snapshot -> CurrentModelSnapshot
```

不存在 Force Apply。输入长度不能超过当前覆盖行，非法/未映射地址会被拒绝。

## `+` 是真实 user 行展开

`+` 只在 Chunk 内仍有未展开的真实 user bytes 时出现。每次点击展开下一行，不写 PhysicalMemory、不扩张 Chunk、不制造 overflow。卡片内部显示行增加后，下面 Chunk 仅为避免 UI 文字重合而整体重排，物理地址不变。
