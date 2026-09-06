# PwnCraft General Pwn Training Protocol

状态：ACTIVE · 2026-09-06

本协议是 PwnCraft **通用 Pwn** 训练入口。历史 `TRAINING_PROTOCOL.md` 继续作为 Heap lane 的锁定专业协议，不覆盖、不重写；当某一轮进入 Heap allocator/PhysicalMemory/Bins 时，同时遵守该专业协议。

## 1. 项目范围

PwnCraft 是 General Pwn Workbench，不是 Heap-only 工具。正式训练域至少包括：

- Stack / saved IP / canary / stack pivot
- Heap / allocator / bins / physical memory
- Format String
- Control Flow：ret2win / ret2libc / ROP / SROP / ORW
- Leak / base derivation
- Syscall / seccomp
- Generic memory read/write
- Integer / bounds / OOB
- IO / FILE / FSOP

一个 domain 的 MATCH **绝不等于**整个 PwnCraft MATCH。

## 2. 真实题目从现在开始进入训练

真实题目训练已开放。每道题在任何 PwnCraft 输出产生之前，必须先完成：

1. 建立 `manifest.json`，固定 binary/EXP/source/libc/ld 等材料身份；
2. 注册唯一 split：`train` / `validation` / `frozen_test`；
3. 通过 `challenge_intake.py` material-readiness + split gate；
4. Phase A clean-room truth 锁定后，才允许 Phase B 运行 PwnCraft。

新上传题如果明确用于训练，默认流程是 **先登记到 train，再分析**；不能先看 PwnCraft 结果后再决定 split。

### Split 硬隔离

- `train`：允许产生 first divergence，并允许该 divergence 驱动通用 patch；
- `validation`：只验证泛化，不允许根据它修改规则；
- `frozen_test`：训练与 validation 完成后才运行最终评估，不允许参与规则选择；
- `unsplit`：BLOCKED。

同一 case 出现在多个 split 是配置错误，直接阻断。

## 3. Clean-room Ground Truth

Phase A 只允许读取题目材料：

- ELF / 其他目标二进制
- source（若有）
- libc / ld（若有）
- 官方或可信 EXP / writeup（若有）
- 独立工具观测：readelf / objdump / checksec / GDB / pwndbg 等

禁止读取当前 PwnCraft 对该 case 的 recognition / capability / IR / snapshot / canvas / diagnostics / divergence report。

每一条 truth 必须带来源；无法证明就写 UNKNOWN。EXP 只能证明 EXP 做了什么，不能替代 target binary truth。

## 4. 通用 Cycle 纪律

```
One Domain Cycle
= One Registered Train Case
= One Earliest Applicable Divergence
= One Minimal Generic Patch
= Train + Validation + Accepted Regression
```

“earliest applicable divergence” 按 domain 的真值链决定，不强行把 Stack/Fmt 塞入 Heap allocator 层序。

修复必须：

- 通用，不允许 challenge name / binary hash / 固定地址特判；
- 有 synthetic unit test；
- 当前 train case 重跑；
- 已 accepted truth regression 不退化；
- 至少一个不同 case/形状用于泛化验证；
- validation/frozen case 不能成为 patch 设计输入。

## 5. Domain truth chains

### Stack / Control Flow

```
Input/EXP evidence
→ cyclic/input-length fact
→ stack frame / saved-IP relation
→ runtime RIP/EIP/PC observation when needed
→ Control RIP primitive
→ gadget/symbol/library constraints
→ ROP/ret2libc/SROP/ORW path
```

`cyclic_find == offset` 只证明 pattern offset；只有真实 RIP/EIP/PC 值与 pattern 对齐，或等价的独立强证据，才能升级为 saved-IP control。

### Heap

继续遵守锁定 Heap 协议：

```
HelperContract → CanonicalIR → TargetBehavior → AllocatorEvents
→ PhysicalMemory → Bins → Snapshot → Canvas
```

### Format String

```
interaction parse
→ format sink/input relationship
→ argument offset evidence
→ read primitive / write primitive（分别证明）
→ width/target/value constraints
```

发现 `printf@plt` 不等于存在格式化字符串漏洞；找到 offset 也不自动等于 arbitrary write。

### Leak

```
raw bytes/text
→ parsed value
→ symbol/module relation
→ base formula
→ typed address
```

每一步保留 provenance，不能只保存最终地址。

### Syscall / Sandbox

```
observed seccomp policy
→ syscall allowed/blocked/unknown
→ exploit path constraints
```

未出现在 dump 中不自动等于 BLOCKED，除非默认动作与分支语义足以证明。

## 6. Runtime truth 与静态 truth 分离

PwnCraft 可以同时使用：

- STATIC / DERIVED：binary/source/EXP 可证明的事实；
- OBSERVED_RUNTIME：GDB/pwndbg 实际寄存器、内存、allocator、FILE 等观测；
- UNKNOWN：当前材料不足。

运行时观测可提升静态候选，但不能反过来把猜测包装成 observed。

## 7. 用户直接提供题目时的材料策略

优先顺序：

1. ELF（二进制最重要）；
2. 题目附带 libc / ld；
3. 已有 EXP；
4. source；
5. writeup / 题目说明。

并非必须全部存在。缺什么就把对应 truth 保持 UNKNOWN；不得为了“训练顺利”补写不存在的证据。

如果只有 ELF，也可以开始静态/运行时训练；如果有 EXP，则还能训练 EXP→target semantics；如果有 source，则可以更强地锁定二进制内部行为。

## 8. 当前阶段

Cycle-8 起已具备：

- 跨域 CaseManifest / domain adapters；
- train/validation/frozen split；
- split-safe `challenge_intake.py`；
- Stack cyclic offset 与 saved-IP control 分离；
- pwndbg-mogai 在 stop event 直接观测 RIP/EIP/PC，并通过 machine protocol 发出 `stack_register_observation`；
- Heap accepted truth regression 继续作为独立历史门禁。

因此从 **Cycle-9 起可以正式以真实 Stack/Fmt/Heap 题轮流驱动训练**。用户下一次提供一套真实 CTF Pwn 材料即可直接登记为 train case；也可以从仓库现有 `splits.json` 的 train 集开始。

## 9. Frozen-test 禁令

当前 `splits.json` 已有 frozen stack case。它不能因为“看起来适合测试 ret2libc”就提前拿来训练。允许在 clean-room 下提前建立锁定 truth，但禁止查看其 PwnCraft 结果、禁止用其 divergence 设计 patch，直到正式 frozen evaluation。
