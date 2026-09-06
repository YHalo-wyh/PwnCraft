# PwnCraft 自动校正 / 真实题训练闭环

PwnCraft 的训练入口现在是 **General Pwn**，不是 Heap-only。

- 通用协议：[`GENERAL_PWN_TRAINING_PROTOCOL.md`](GENERAL_PWN_TRAINING_PROTOCOL.md)
- Heap 专业协议：[`TRAINING_PROTOCOL.md`](TRAINING_PROTOCOL.md)（历史 LOCKED，进入 allocator/PhysicalMemory/Bins lane 时继续生效）
- 项目范围：[`pwn_scope.json`](pwn_scope.json)
- 真实题 split gate：`challenge_intake.py`
- 数据划分：`splits.json`（train / validation / frozen_test）

## 真实题训练硬流程

```text
题目材料
→ manifest + split 注册
→ challenge_intake gate
→ Phase A clean-room expected truth
→ Phase B PwnCraft baseline
→ earliest applicable divergence
→ minimal generic patch
→ project + accepted truth regression
→ validation generalization
→ frozen evaluation（最后）
```

`validation` 与 `frozen_test` 永远不能作为 patch feedback。新题未注册 split 时保持 BLOCKED。

## Domain adapters

`domain_adapters.py` 按领域选择真值链：

- heap：Helper/Canonical/TargetBehavior/Allocator/PhysicalMemory/Bins/Snapshot/Canvas；
- stack：EXP/Binary/Stack-runtime/ControlFlow 逐步扩展，不套 allocator 层；
- fmt：EXP parse / interaction / format semantic facts，后续继续加入 offset/read/write truth。

跨域共享事实写入 PwnWorkspace，但各 domain 保留自己的 engine/provider 精度。

## 当前状态（Cycle-8）

- Stack cyclic offset 与 saved RIP/EIP/PC control 已分离；
- pwndbg-mogai stop event 可发出真实 `stack_register_observation`；
- 只有观测到的控制寄存器值能被 deterministic cyclic decoder 命中时，才升级为 `confirmed_control`；
- train/validation/frozen split 已有可执行 intake gate；
- Heap 已 accepted 的 lab13 / note2 truth regression 仍持续作为独立门禁。

因此下一轮可直接开始真实 Stack/Fmt/Heap train case。用户也可以直接提供新的 ELF/libc/ld/EXP/source/writeup；材料缺失的部分保持 UNKNOWN，不会为了训练而猜。
