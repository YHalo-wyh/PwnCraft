# cycle-8 — Runtime Stack Truth + Real-Challenge Intake

状态：ACCEPTED（2026-09-06）

分支：`main`（用户已授权直接修改）

Domain：`stack / control_flow / project-training-infrastructure`

## 本轮目标

Cycle-7 已把 PwnCraft 从 Heap-only curriculum 修正为 General Pwn，但 Stack 的 `confirmed_control` 仍主要依赖调用方声明“这是 RIP/EIP/PC”。Cycle-8 要解决两个基础问题：

1. **真实 debugger observation 必须成为 saved-IP control 的强证据**；
2. **真实题必须有 train/validation/frozen 隔离后才能进入训练**。

这两项完成后，下一轮开始不再只做 synthetic foundation，可以正式让真实 Pwn challenge 驱动 first divergence。

## Stack runtime truth

### `core/stack_truth.py`

新增 `RuntimeRegisterObservation` 与 `derive_saved_ip_control_from_observation()`：

```text
observed RIP/EIP/PC value
→ deterministic cyclic_find(observed_value)
→ offset
→ confirmed_control
```

关键纪律：

- SIGSEGV 不是 Control RIP 证据；
- 只允许 `rip/eip/pc`；
- 寄存器值必须真实存在；
- observed value 不在 cyclic pattern 中时直接失败，不能升级 capability；
- `confirm_saved_ip_control()` 仅保留兼容路径，新 runtime 集成必须走 observed-value 路径。

### pwndbg-mogai bridge

`third_party/pwndbg-mogai/.../bridge/runtime.py` 在 GDB stop event 直接读取真实 `$rip/$eip/$pc`，发出：

`stack_register_observation`

payload 带：register / value / value_hex / signal / stop_reason / provenance=`OBSERVED_RUNTIME`。

不解析终端显示文本，不根据架构名字猜寄存器，不因为崩溃信号自动宣称 control。

### `runtime_truth_router.py`

新增 debugger machine-fact → Workspace 的通用路由器：

- raw register observation 总是可进入 `Workspace.runtime` 作为 observed fact；
- 只有 cyclic correlation 成功才发布 `Workspace.stack` confirmed truth；
- 不相关 machine message 保持 ignored；
- non-pattern RIP 只记 observed，不产生 Control RIP。

### Stack domain adapter

`autocorrect/domain_adapters.py` 新增可选 `STACK_RUNTIME_TRUTH`：

- 无 runtime sidecar → SKIPPED；
- 有 SIGSEGV 但 RIP 不命中 cyclic → SKIPPED；
- RIP/EIP/PC 真实值命中 → MATCH + `confirmed_control` truth。

这层是 optional，不要求所有离线 Stack case 必须执行 binary。

## Real challenge intake

### `challenge_intake.py`

把 `splits.json` 从“数据文件”提升为可执行训练门禁：

- `train`：允许 first divergence 驱动 patch；
- `validation`：evaluate-only；
- `frozen_test`：最终评估专用；
- `unsplit`：BLOCKED；
- 同 case 出现在多个 split：配置错误，直接阻断；
- binary/EXP 等 required materials 缺失：即使在 train 也 BLOCKED。

`build_truth` 可以在已注册 split 上 clean-room 执行，但 validation/frozen 的 PwnCraft 输出不能参与 patch 设计。

### `GENERAL_PWN_TRAINING_PROTOCOL.md`

新增通用训练协议。历史 `TRAINING_PROTOCOL.md` 不改写，继续作为 Heap allocator lane 的锁定专业协议。

通用协议正式覆盖：Stack / Heap / Format / ControlFlow / Leak / Syscall-Sandbox / MemoryWrite / Integer / IO-FILE。

`pwn_scope.json` schema 升到 2，并将：

`real_challenge_training = READY`

写入 scheduler。

## Tests

新增/扩展：

- `pwncraft/tests/test_stack_runtime_truth_v2.py`
- `pwncraft/tests/test_runtime_truth_router.py`
- `autocorrect/tests/test_challenge_intake.py`
- `autocorrect/tests/test_stack_domain_runtime.py`

覆盖：

- RIP n=8 / EIP n=4 observed correlation；
- non-pattern RIP 不升级；
- signal-only 不升级；
- machine observation 保留但 capability 仍 UNKNOWN；
- train/validation/frozen/unsplit 隔离；
- duplicate split 阻断；
- material-incomplete train case 阻断；
- Stack adapter optional runtime truth。

## 正式门禁

GitHub Actions `Recognizer training gate` run #79（代码 head `1655e114e8017c303ec83687e0b0a6ba7ad876d0`）：

- project regression：`493 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`30 passed`；
- accepted Heap truth regression：
  - lab13 `MATCH`；
  - note2 `MATCH`；
- gate：`failed=False -> exit 0`。

因此本轮接收。

## 什么时候开始拿真题训练

**现在已经可以。**

从 Cycle-9 开始可直接使用真实 train challenge 驱动训练。两种入口都支持：

1. 用户直接提供新的 ELF（可附 libc/ld/EXP/source/writeup）→ 先 manifest + train split → clean-room truth → PwnCraft baseline；
2. 从仓库 `splits.json` 已有 train case 中选题。

明确禁止把当前 frozen-test 的 ret2libc3 case 提前用于 patch feedback。

## 当前仍未冒充闭环的部分

Electron 主进程目前仍把 debug PTY 原始字节直接转发 renderer；本轮已经具备 pwndbg machine-message producer 与 Python Workspace truth router，但 **OSC machine frame 的 Electron 自动 decode/forward 还未接上**。因此：

- 训练/评测可直接消费结构化 runtime sidecar；
- pwndbg 已能产生正确 observation；
- Python 已能正确接收并判定 observation；
- GUI 内“一停下就自动刷新 Stack/Capability”的最后 transport glue 留作产品集成轮，不把它虚报为已完成。

下一轮优先正式进入一个 `train` Stack challenge 的 clean-room truth + first divergence；Heap PHYSICAL_MEMORY lane 保持交错继续。
