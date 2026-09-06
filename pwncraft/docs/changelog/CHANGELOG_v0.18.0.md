# v0.18.0

本轮收口 Phase 3：SROP Builder。至此规划 §十三 Syscall 模块中 Explorer / Planner / ORW / SROP / Seccomp 五个能力全部落地（Seccomp 为全局约束）。

## SROP Builder（BUILD，§八/§十三）

- 新增 `pwncraft/core/srop.py`：`SROPBuilder` / `SigreturnPlan`。
- **诚实建模边界**：本项目不手写 sigcontext/ucontext 二进制偏移；帧布局真值由生成代码中的 pwntools `SigreturnFrame` 在 EXP 运行时提供。模型侧只建模可验证事实：
  - 帧寄存器赋值（rax=目标 syscall 号、参数寄存器、rip=syscall Gadget 证据地址、rsp=`FRAME_ADDR` inferred 占位）；
  - 三个触发控制点及其证据：`rax=15`（pop rax）、`rsp→frame`（pop rsp 或 `leave ; ret`）、`rip→syscall`（syscall Gadget）；
  - Seccomp 双判定：目标 syscall 与 `rt_sigreturn` 任一 BLOCKED 即 blocker；UNKNOWN 只警告、不当作允许（计划不可执行）。
- 参数控制 Gadget 被刻意不要求：sigreturn 时全部寄存器由帧恢复，这是 SROP 语义本身。
- 仅支持 amd64；i386/aarch64 帧布局不同 → 如实返回「不支持」诊断，不伪造。
- `to_pwntools()` 仅在计划可执行时导出骨架代码；`to_dict()` JSON 安全。
- `tool_actions` 注册 `srop.build`（BUILD：preview/validate/save_stage/generate_pwntools/insert_to_exp）。

## GUI

- Syscall 页第 4 个子页从 Coming later 占位替换为真实 `SropBuilderPanel`：目标 syscall + 参数表单 → 「诊断 SROP 计划」（控制点证据、Seccomp 判定、blockers、帧寄存器视图）→ 全部可执行才解锁「预览 pwntools」→ `_CodePreviewDialog` 确认后经既有 `insertRequested → _insert_exp_block` 插入（Ctrl+Z 可撤销）。
- Explorer / Planner 仍为 QUERY，无 EXP 插入按钮；`workspace_merged` 后 SROP 面板重置。

## Phase 3 完成状态

```
Seccomp Parser        ✔（v0.17，结构化 + unknown 语义）
Syscall Planner       ✔（v0.17，寄存器/Gadget/Seccomp 三合一诊断）
ORW Builder           ✔（v0.17，逐步事实诊断）
SROP Builder          ✔（本轮）
遗留：syscall chain 动态 fd 数据流模拟（open 返回值 → read 的自动传递）
```

## 验证

- 新增 `tests/test_srop_phase3.py`（11 项）与 SROP GUI 测试（3 项）；Phase 3 合计 37 passed。
- 全量回归：**349 passed, 1 skipped**；Heap semantic benchmark 通过；py_compile 通过。
- 官方 pwndbg 未修改。

## 未完成边界（后续阶段）

- Phase 3 遗留：syscall chain 动态 fd 数据流。
- Phase 4：Libc Workspace、one_gadget 约束引擎。
- Phase 6：Format String Lab；Phase 7：Capability Graph / Stage 工作流；Phase 8：AI Tutor。
