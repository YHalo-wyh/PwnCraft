# v0.14.1

- 修正命令面板：Binary、Gadget、Syscall、Encoding 现在打开对应的 Workbench 子页，不再误跳到 IO FILE。
- 修正 checksec 字段解析边界，Not found、No、Disabled 不会被相邻的 Found 误判。
- 修正编码输入越界，负数和超宽整数统一报告为 ValueError。
- EXP 编辑内容同步保存到 Workspace，包含 source_hash，避免各页面各自维护一份 EXP。
- Workbench 增加共享变量页；Gadget、Syscall、Encoding 的结果可以在 Workspace 中追溯来源并复制。
- Heap 当前模型向 Workspace 发布轻量 JSON 安全摘要，保留 allocator replay 作为唯一详细事实来源。
