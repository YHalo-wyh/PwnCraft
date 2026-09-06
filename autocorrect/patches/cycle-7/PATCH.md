# cycle-7 — General-Pwn scope guard + Stack truth foundation

状态：ACCEPTED（2026-09-06）

分支：`main`（用户已授权直接修改）

目标阶段：`PROJECT_SCOPE / CROSS_DOMAIN_FOUNDATION / STACK_CONTROL_TRUTH_FOUNDATION`

## 为什么这一轮不继续只盯 PHYSICAL_MEMORY

Cycle-1～6 的正式训练 lane 主要集中在 Heap EXP 识别、TargetBehavior 和 allocator truth。这个 lane 本身仍然需要继续，但它不能被错误理解为 PwnCraft 的全部能力。

PwnCraft 已有 Stack、ROP、SROP、ORW、Format String、Leak、Syscall/Seccomp、Binary/IDA/Pwndbg 等组件；如果 curriculum 继续只有 heap case，就会产生结构性偏差：

- heap MATCH 被误当成整个项目能力提升；
- `Capability Analyzer` 已读取 `Workspace.stack/gadgets/leaks/syscalls`，但训练 curriculum 没有统一的跨域状态模型；
- 空 Workspace 或仅有 Stack 证据时，项目级视图不应默认把 Heap 当主域；
- Format/Stack/Leak 等证据必须和 Heap 一样遵守“不知道就 unknown”的纪律。

因此 Cycle-7 先修正项目级训练方向，并立即落下第一条非 Heap truth lane：Stack control truth foundation。

## General-Pwn project scope

新增 `autocorrect/pwn_scope.json`，正式声明项目级 scope 为 `general_pwn_workbench`。

硬规则：

1. 每个训练/审计 cycle 必须声明所属 domain；
2. 一个 domain 的 MATCH 不能外推为整个 PwnCraft 已闭环；
3. 跨域共享事实进入 `PwnWorkspace`，域内真值仍由各自 engine/provider 持有；
4. 没有证据时保持 `unknown`，不得因为 GOT/PLT、危险函数名或页面存在就判定某类漏洞；
5. curriculum 采用 `cross_domain_interleave`：Heap 可以继续做深，但必须与 Stack / Format / ControlFlow / Leak 等 lane 交错推进。

当前同时保留：

- `heap_physical_memory_truth`
- `stack_control_truth_foundation`

后续队列还包括 Format String、Control Flow/Gadget chain、Leak provenance，以及更后面的 integer/OOB、FILE/FSOP 等专用域。

## 新增：`core/pwn_surface.py`

新增通用 `PwnDomain` / `DomainAssessment` / `DOMAIN_CATALOG`，当前覆盖：

- stack
- heap
- format_string
- control_flow
- leak
- syscall_sandbox
- memory_write
- integer
- io_file

`analyze_pwn_surface(workspace)` 只消费当前 Workspace 已存在的事实，输出 `evidenced / partial / unknown`。它是 surface assessment，不是漏洞扫描器。

关键不变量：

- 空 Workspace 不默认属于 Heap；
- Heap 只有模型状态而无显式 heap primitive 时最多 `partial`；
- Stack、Heap、Format、Leak、Seccomp 可以独立存在；
- Format String Write 可同时属于 `format_string` 与 generic `memory_write`；
- project surface 不把某个 domain 的证据传播成其他 domain 的“已确认漏洞”。

## 第一条非 Heap truth lane：Stack

新增 `pwncraft/core/stack_truth.py`。

最重要的修正是把过去混在一起的两个事实拆开：

1. `cyclic` 崩溃值能反推出 offset；
2. 保存的 `RIP/EIP/PC` 确实被该输入覆盖。

它们不是同一件事。

新增 `StackOverflowEvidence`：

- `offset`
- `crash_value`
- `pattern_n`
- `source`
- `control_register`
- `state = offset_only | confirmed_control`

`derive_cyclic_overflow()` 只做确定性的 cyclic 反解，结果固定为 `offset_only`，不能直接宣称 Control RIP。

`confirm_saved_ip_control()` 只有拿到明确的 `RIP/EIP/PC` 覆盖证据后才升级到 `confirmed_control`；传入普通寄存器会被拒绝。

`publish_stack_evidence()` 把这份 JSON-safe 真值发布到 `Workspace.stack`，供 Workbench / Capability / 后续 debugger bridge 使用。

为兼容旧 `.pwncraft` 项目，历史上只保存 `overflow_offset` 而没有 provenance 字段的状态被显式标记为 `legacy_offset`；不会破坏旧项目，但新数据不再走这条宽松路径。

## Capability truth 修正

`core/capability.py` 同步收紧：

### Control RIP

- 显式 `Control RIP` primitive → available；
- `confirmed_control` + RIP/EIP/PC observed → available；
- 新式 `offset_only` → **unknown**，并提示还需确认 saved IP overwrite；
- 旧项目 bare `overflow_offset` → legacy compatibility；
- 无证据 → unknown。

因此“找到了 cyclic offset”不再被当成“已经控制程序计数器”。

### Format String

修掉一个跨域假阳性：旧逻辑里 `bool(plt)` 也会让 Format String capability 出现。普通 ELF 有 PLT 完全不能证明格式化字符串漏洞。

现在只有显式 Format primitive 或已记录的 `format_offset` 才激活该 lane，而且 offset 本身仍不自动升级为 arbitrary read/write。

### Leak → libc_base

另一个跨页断层也补上了：Stack/Leak 页的 `rpc_leak_derive` 历史上把 `libc_base` 写成 typed `WorkspaceVariable`，而 Capability Analyzer 主要读取 `workspace.libraries.libc_base`。

现在 capability truth 同时接受这两种 **已有证据的 Workspace 表达**，因此 Leak 页推导出的 typed libc base 能进入 ret2libc capability 分析；无法解析的 symbolic/unknown 值不会被强转成地址。

## 测试

新增 `pwncraft/tests/test_pwn_surface.py`：

- 空 Workspace 不默认 Heap；
- Stack 与 Heap 可独立激活；
- Heap model facts 只有 partial，显式 heap primitive 后才 evidenced；
- Format String Write 同时进入 Format + MemoryWrite；
- Seccomp 与 Leak 是独立 surface；
- project catalog 覆盖全部当前 Pwn domains。

新增 `pwncraft/tests/test_stack_truth.py`：

- cyclic 反解只得到 `offset_only`；
- offset-only 不会产生 Control RIP；
- RIP runtime observation 才升级为 available；
- 非 RIP/EIP/PC 寄存器确认被拒绝；
- legacy bare offset 保持旧项目兼容；
- 非空 PLT 不是 Format String 证据；
- format offset 不是 arbitrary write 证明。

新增 `pwncraft/tests/test_cross_domain_capability_truth.py`：

- typed WorkspaceVariable `libc_base` 可被 ret2libc capability 消费；
- 不可解析的 libc_base 不会被当成有效地址。

新增 `autocorrect/tests/test_pwn_scope_contract.py`：

- scope 必须是 general Pwn；
- 至少覆盖 stack/heap/format/control-flow/leak/syscall；
- scheduler 必须同时存在 heap 与 non-heap lane；
- 单域 MATCH 不得外推全项目。

## 正式门禁

GitHub Actions `Recognizer training gate` run #64（代码 HEAD `4176424484f89e614fa90523895cf1dea6f60334`）：

- project regression：`485 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`21 passed`；
- accepted heap truth regression：
  - lab13 `MATCH`；
  - note2 `MATCH`；
- gate：`failed=False -> exit 0`。

因此 Cycle-7 的 project-scope guard 与 Stack truth foundation 一并接收。

## 当前边界 / 下一轮

本轮没有声称 Stack 已完整闭环：当前 `electron_bridge.rpc_cyclic_find` 仍只是返回 offset，尚未自动把 `offset_only` evidence 发布进 Workspace；调试器/pwndbg 的真实 RIP/EIP/PC observation 也还没有接到 `confirm_saved_ip_control()`。

下一轮 Stack lane 的 first divergence 已明确：

`Stack 页面 cyclic_find` → `Workspace.stack offset_only` → `Debugger/pwndbg observed saved-IP overwrite` → `confirmed_control` → `Capability Analyzer`

同时 Heap lane继续从 lab13 `PHYSICAL_MEMORY` 往 `BINS` 推进。之后再轮换到 Format String evidence lane，避免 curriculum 再次被单一 Heap domain 垄断。
