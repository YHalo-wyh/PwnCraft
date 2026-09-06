# pwn宝 v0.3.0

## 按写 EXP 习惯收敛

- 格式化字符串面板默认聚焦模块化 low/high、泄漏 payload、两次 `%hn` 覆盖 payload。
- 格式化字符串片段默认只构造 payload，不再自动加入固定发送/收包循环。
- 高频代码块和堆代码生成尽量改为 `payload += p32()/p64()` 的手动拼接写法，减少默认 `flat()` 使用；复杂场景仍保留高级备用入口。
- 新增变量名驱动的 low/high 进制转换结果，默认变量名 `system_addr`。

## 堆可视化 / 语义

- 修正 glibc `request2size`：按 `SIZE_SZ` 计算，amd64 `malloc(0x68)` 显示为 `0x70`。
- bin 状态改为互斥维护；malloc 复用会从 tcache/fastbin/smallbin 移除旧节点并标记 stale alias。
- consolidate 后刷新 unsorted fd/bk，展示 main_arena 和双链关系。
- chunk 卡片改为更宽松字段表，按架构显示 `+0x00/+0x08/+0x10/+0x18` 或 i386 对应偏移。
- 画布增加 fd/bk 字段到 Bin 区的方向提示线。
- 堆面板支持“吸收选中 EXP”，轻量解析 `add/delete/edit/show` 调用追加到语义时间线。

## 测试

- 新增 request2size、bin 互斥/复用、fastbin->unsorted、conversion low/high、i386 fmt 模板、chunk 字段偏移和 EXP 吸收解析回归。

## v0.3.1 调整

- 堆画布去掉顶部步骤标题、说明、图例和 fd/bk 箭头小标签；默认 1:1 显示，不再为了适配宽度压缩字体。
- Heap 生成代码移除 `# pwnbao:heapviz begin/end` 和 `# pwnbao:op` 注释，左侧 EXP 只保留普通 `add/delete/edit/show` 代码。
- 格式化字符串面板改为模块化片段，不再提供整份 exp 插入：low/high、`p32(addr)+%s`、两次 `%hn` payload 分开生成，发送方式可自定义。
- 进一步压缩 chunk 卡片宽度、增大字段行高、隐藏空 bin 组和无意义 note 行，默认画布更接近“只有 chunk 图和内容”。
- 修复连续添加 chunk 时默认 data 固定为 `b'A'` 的问题；`add chunk B/C/...` 会自动推进为 `b'B'`、`b'C'`，手写 payload 不会被覆盖。
- 左侧新增 heap 偏移纵轴，顶部标 `heap_base`，tick 显示 `+0x290` 这类偏移，chunk 地址不再写入方块；复用/重叠的物理区间用错位叠放和虚线背景框展示，轴上标出 `overlap×N`。
- 修复语义表单隐藏字段泄漏：普通 alloc 不再继承 target 输入框默认的 `__free_hook`，避免轴地址错误。
- chunk header 改为两行元信息，完整显示 `state=allocated`、index、request、chunk size，避免右侧状态被截断成省略号。
- 左侧 EXP 编辑器保持可编辑，新增黄色操作线；拖动左侧圆点会吸附到最近的堆操作模块并驱动右侧快照，不再靠选中文本才能定位。
- 轻量 EXP 解析支持 `for i in range(...):`，例如 `for i in range(8): add(0x100, i)` 会展开成 8 个 alloc 语义步骤。
- 堆面板新增 heap base 输入；默认 `heap_base`，也可填 `0x555555559000` 这类具体值，模拟器会计算 chunk 地址和字段地址，画布轴仍显示 `heap_base + 偏移` 视角。
