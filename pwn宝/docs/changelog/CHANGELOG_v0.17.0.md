# v0.17.0

本轮严格按总规划完成 Phase 3（Syscall + Seccomp）第一步：Syscall Planner + Seccomp 全局约束 + 受约束的 ORW Builder。SROP 按规划保留诚实占位，不伪造 SigreturnFrame。

## Syscall Truth 模型（§十四/§十五）

- 三架构 syscall 表扩充至 `read/write/open/openat/close/execve/exit/mmap/mprotect/dup2`：
  - i386 使用真实编号（mmap2=192、exit=1 等）与 `eax` 返回寄存器。
  - aarch64 补齐 close/exit/mmap/mprotect；**无 dup2**（只有 dup3），表中保持缺席即 unknown，不伪造。
- `SyscallSpec` 增加 `return_register` / `architecture`，支持 `to_dict/from_dict` round-trip。
- `normalize_architecture(strict=True)` 对未知架构抛错；默认回退 amd64 保持旧调用方兼容。
- 新增 `parse_seccomp_policy_structured()`：保留平面 `ALLOWED/BLOCKED` 兼容视图，额外记录 default action、参数过滤原文（标 unknown，不猜 verdict）与来源行。
- 新增 `seccomp_verdict()`：无显式条目返回 `UNKNOWN`——缺席不等于允许。

## SyscallPlanner 诊断（§十五）

- 新增 `diagnose()`：一次性给出寄存器映射、缺失参数、Gadget 控制缺口（含缺失寄存器名）、Seccomp verdict 与不可执行原因列表。
- `SyscallPlan` 新增 `seccomp_verdict` / `blockers` / `executable` / `to_dict()`；`executable` 要求寄存器完整 + Gadget 控制 + Seccomp 非 BLOCKED。
- BLOCKED 永远不可执行；UNKNOWN 只提示、不当作允许。

## ORW Builder（§十七，BUILD 子集）

- 新增 `pwnbao/core/orw.py`：`ORWBuilder/ORWReport/ORWStep` 结构化表示 `open/openat -> read -> write`。
- 每步用真实 Workspace 事实诊断：缺 syscall、缺控制 Gadget、Seccomp BLOCKED、架构不支持都生成失败诊断，不生成错误 payload。
- `auto` 变体优先选参数寄存器更少、可证明性更高的 `open`（3 regs）；显式选 `openat` 时如实报告 R10 缺口。
- open 返回的动态 fd 是显式 `inferred` 占位（`fd=OPEN_FD`），必须由用户在运行时确认；报告与警告如实标注。
- SROP 不实现后端，Syscall 页保留 Coming later 占位。

## GUI（Syscall 页）

- Syscall 页升级为四个子页：`Explorer / Planner / ORW Builder / SROP(占位)`。
- Planner：选择 syscall（随 Binary 架构联动）、按别名填参数、展示寄存器映射/Seccomp/缺失 Gadget；缺 Gadget 时一键跳转 ROP→Gadget Explorer 并预填搜索。
- ORW Builder：Path/buffer/size/output fd 表单 + 三步诊断卡；全部步骤可执行才允许「预览 pwntools」，插入仍走 Preview→确认→Insert（可 Ctrl+Z），不自动改写 EXP。
- Explorer/SROP 区无 EXP 插入按钮；Explorer 只查询事实。
- 项目重载（`workspace_merged`）后 Planner/ORW 从 Workspace 刷新。
- 主窗口接通 `syscall_page.insertRequested → _insert_exp_block`、`findGadgetRequested → _goto_gadget_search`。

## 测试

- 新增 `tests/test_syscall_phase3.py`（17 项：表边界/序列化/seccomp 结构化/诊断正反路径/ORW 计划）与 `tests/test_syscall_phase3_gui.py`（6 项：页签结构/BLOCKED 判定/Gadget 跳转/Preview 门控/插入信号/重载刷新）。
- 全量回归：**335 passed, 1 skipped**；Heap semantic benchmark 通过；py_compile 通过。
- 官方 pwndbg 未修改。

## 未完成边界（后续阶段）

- Phase 3 剩余：SROP Builder、Syscall chain 级编排（动态 fd 数据流模拟）。
- Phase 4：Libc Workspace、one_gadget 约束引擎。
- Phase 6：Format String Lab；Phase 7：Capability Graph；Phase 8：AI Tutor。
