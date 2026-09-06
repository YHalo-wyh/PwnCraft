# v0.13.2

- pwndbg-mogai 启动时强制 `disable-colors=off`，并安装高对比 banner/register/highlight 主题。
- Terminal History 改为滚轮每格逐行滚动，工作区增加同步纵向滚动条。
- 移除 Pwndbg 页面的“独立配置/真 PTY/官方不受影响”重复说明条。
- 已有 Chunk 不再是可移动卡片；取消上下/左右拖动、自由布局、对齐和任意尺寸修改。
- 上/下边手柄改为 underflow/overflow 覆盖延伸；手柄所属 Chunk 是覆盖主体。
- 被覆盖 Chunk 的名称 header 同步变色；覆盖 payload 默认空白，点击后才通过 PhysicalMemory/ConstraintEngine 写入。
