# pwn宝 v0.2.0

## 堆可视化重构

- 堆模式改为左侧完整 EXP、右侧 Heap/Bin 图；自动隐藏积木侧栏和底部日志。
- 主 EXP 与堆模式 EXP 双向同步。
- 光标或选区定位到 `# pwnbao:op` 代码段时，时间线与右侧快照同步切换；选择时间线也会反向选中代码段。
- 使用 Qt 原生 scene 图元代替 Python 自定义 `QGraphicsItem`，避免连续添加 chunk、切换快照时的对象生命周期闪退。
- Chunk 固定表格布局，展示 address、request、size、state、fd/next、bk、data、bin、note；长内容省略但可通过 tooltip 查看全文。
- Chunk 按低地址到高地址从上往下排列。
- tcache、fastbin、unsorted、smallbin、largebin 单独绘制链头、节点及单/双向箭头。
- 单击 chunk 查看详细字段；双击或点击工具栏可把地址插入 EXP。
- 语义时间线改成多列表格，警告和 exploit primitive 可直接查看。
- freed chunk 会显示模拟的 fd/bk metadata；safe-linking 环境显示 `PROTECT_PTR(pos, next)` 语义。

## EXP 与模板修复

- 修复 fake chunk、main_arena leak、setcontext 模板生成真实 NUL，导致 EXP 无法编译的问题。
- 修复 safe-linking 模板生成非法 `poisoned fd` 文本和未编码 fd 的问题。
- fake chunk 字段偏移会根据 i386/amd64 使用 4/8 字节字宽。
- i386 任务不再展示明显依赖 p64/setcontext 的堆模板。
- 修复超过字宽的字节输入生成无效 `u32/u64` 代码的问题。

## 组件库

- “常用”和“最近使用”的积木不再在原分类中重复显示。
- 默认折叠低频分类，搜索时自动展开命中分类。
- 搜索同时匹配 block ID。
- 修改任务架构/libc 配置不再直接清空已有 EXP。

## 稳定性

- 场景加载处理损坏 JSON、未知操作和 I/O 异常。
- 覆盖/清空场景前增加确认。
- 场景操作加载后重新编号，避免重复 `op_id`。
- 增加核心生成器和无界面 GUI 回归测试。
