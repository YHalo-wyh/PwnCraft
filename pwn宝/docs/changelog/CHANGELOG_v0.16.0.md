# v0.16.0

本轮严格按《Pwn宝下一代 Pwn Workbench 大改开发任务》完成 Phase 2（Stack + ROP）接线与可验证子集收口。

## Phase 2 已完成

- 修复 ROP/Stack GUI 阻断：Chain Builder、ret2libc Wizard 使用合法的 Qt parent 接线；Stack 导航正式挂载已有 `StackPage`，不再显示占位页。
- 主窗口新增 `_insert_exp_block()` 兼容入口。Builder 输出继续经过 Preview → 用户确认 → QTextCursor 插入；不覆盖整个 EXP，保留原生 Ctrl+Z。
- `PwnWorkspace.set_current_chain()` 现在会反序列化并校验 Chain：`word_size` 仅允许 4/8，entries 必须连续，未知值和非法结构明确拒绝；规范化 Chain 带 schema/title/bits/state 元数据。
- 增加 `add_stage()` / `update_stage()`，ROP Chain 保存和 ret2libc Leak Chain 记录真实 draft Stage，保存 title/type/status/inputs/outputs/source/runtime 字段。
- 打开 `.pwnbao` 后 Stack Canvas、ROP Builder、ret2libc、Leak Manager 订阅 `workspace_merged` 并刷新，runtime 继续标 stale。

## ROP 语义

- `ROPChain.validate()` 检查 word size、offset 连续性、未知值、memory side effect 和非 ret 结束 Gadget。
- `ROPChain.to_stack_state()` 使用同一 word_size/offset 规则物化栈，避免 StackState 与 current_chain 产生第二份布局真值。
- `simulate()` 依照 Gadget controls 消费多个 pop 槽位，trace 保留 consumed register/value/offset 和寄存器变更；兼容旧版 trace 数量约定。
- 复杂 memory side effect Gadget 继续拒绝；不猜地址、不伪造 runtime/allocator 事实。

## 明确未完成

- ORW、SROP、完整 Seccomp Planner：Phase 3。
- Libc 数据库、one_gadget 约束引擎：Phase 4。
- Format String Lab：Phase 6。
- Exploit Capability Graph、完整 Stage 工作流和 AI Tutor：后续阶段。

## 验证

- `python -m py_compile`：通过。
- Phase 2 相关测试：39 passed。
- 全量回归：**312 passed, 1 skipped**。
- Heap semantic benchmark：通过，末项 `unsorted_corruption_consumed` PASS。
- 官方 pwndbg 环境未修改；仍只使用独立 `third_party/pwndbg-mogai`。
