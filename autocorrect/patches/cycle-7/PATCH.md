# cycle-7 — General-Pwn scope guard + cross-domain surface model

状态：ACCEPTED（2026-09-06）

分支：`main`（用户已授权直接修改）

目标阶段：`PROJECT_SCOPE / CROSS_DOMAIN_FOUNDATION`

## 为什么这一轮不继续只盯 PHYSICAL_MEMORY

Cycle-1～6 的正式训练 lane 主要集中在 Heap EXP 识别、TargetBehavior 和 allocator truth。这个 lane 本身仍然需要继续，但它不能被错误理解为 PwnCraft 的全部能力。

PwnCraft 已有 Stack、ROP、SROP、ORW、Format String、Leak、Syscall/Seccomp、Binary/IDA/Pwndbg 等组件；如果 curriculum 继续只有 heap case，就会产生结构性偏差：

- heap MATCH 被误当成整个项目能力提升；
- `Capability Analyzer` 已读取 `Workspace.stack/gadgets/leaks/syscalls`，但训练 curriculum 没有统一的跨域状态模型；
- 空 Workspace 或仅有 Stack 证据时，项目级视图不应默认把 Heap 当主域；
- Format/Stack/Leak 等证据必须和 Heap 一样遵守“不知道就 unknown”的纪律。

因此 Cycle-7 先修正项目级训练方向，再继续各 domain 的深层 truth closure。

## 新增：`core/pwn_surface.py`

新增通用 `PwnDomain` / `DomainAssessment` / `DOMAIN_CATALOG`：

- stack
- heap
- format_string
- control_flow
- leak
- syscall_sandbox
- memory_write
- integer
- io_file

`analyze_pwn_surface(workspace)` 只消费当前 Workspace 已存在的事实，输出 `evidenced / partial / unknown`。

硬约束：

1. 它是 **surface assessment**，不是漏洞扫描器；
2. 不因为 GOT/PLT、危险函数名、某个页面存在就判定漏洞；
3. Heap 只有模型状态而无显式 heap primitive 时最多为 `partial`；
4. 空 Workspace 所有域均保持 unknown，`active_domains()` 不默认返回 heap；
5. Stack 的 `overflow_offset` 可以独立激活 Stack + Control Flow，而不会把 Heap 一起激活；
6. Format String Write 可以同时属于 format_string + generic memory_write，这是跨域事实，不要求塞进 Heap 模型。

该模块已从 `pwncraft.core` 导出，后续 Workbench、训练调度器和审计报告都可以消费同一份 domain projection。

## 新增：`autocorrect/pwn_scope.json`

正式写入项目级 scope：`general_pwn_workbench`。

其中明确：

- HeapViz/allocator 是专业 lane，不是 PwnCraft 全部；
- 每个训练/审计 cycle 必须声明 domain；
- 一个 domain 的 MATCH 不能外推为整个项目闭环；
- 跨域共享事实进入 PwnWorkspace，域内真值继续由各自 engine/provider 持有；
- curriculum 使用 `cross_domain_interleave`，Heap 可以继续做深，但必须与 Stack/Format/ControlFlow/Leak 等 lane 交错推进。

当前 active lanes：

- `heap_physical_memory_truth`
- `stack_control_truth_foundation`

下一阶段队列同时保留：

1. Stack：cyclic/崩溃证据 → saved RIP offset truth → Control RIP；
2. Heap：lab13 PHYSICAL_MEMORY → BINS；
3. Format String：显式 offset/read/write evidence；
4. Control Flow：gadget role + chain validation；
5. Leak：保留 provenance 的基址推导。

## 回归

新增 `pwncraft/tests/test_pwn_surface.py`：

- 空 Workspace 不默认 Heap；
- Stack offset 独立激活 Stack/ControlFlow；
- Heap model facts 只有 partial，显式 UAF primitive 后才 evidenced；
- Format String Write 同时进入 Format + MemoryWrite；
- Seccomp 与 Leak 是独立 surface；
- project catalog 必须覆盖所有通用 Pwn domains。

新增 `autocorrect/tests/test_pwn_scope_contract.py`：

- scope 必须是 general Pwn；
- 必须至少覆盖 stack/heap/format/control-flow/leak/syscall；
- scheduler 必须同时存在 heap 与 non-heap active lane；
- 硬规则禁止单域 MATCH 外推全项目。

## 正式门禁

GitHub Actions `Recognizer training gate` run #57：

- project regression：`477 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`21 passed`；
- accepted heap truth regression：
  - lab13 `MATCH`；
  - note2 `MATCH`；
- gate：`failed=False -> exit 0`。

因此 Cycle-7 接收。

## 当前边界

本轮只建立 **跨域项目真值/训练边界**，没有声称以下能力已经闭环：

- Stack runtime crash → offset → saved RIP 的完整 provenance 链；
- Format String 的实际漏洞确认；
- 任意写 primitive 的自动确认；
- lab13 PHYSICAL_MEMORY/BINS；
- FSOP / integer/OOB 的专用 engine。

下一轮优先进入 `stack_control_truth_foundation`，同时保留 Heap PHYSICAL_MEMORY lane；后续不再按“堆训练 = 整个 PwnCraft 训练”的方式推进。
