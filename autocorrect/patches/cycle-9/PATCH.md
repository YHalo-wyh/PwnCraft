# cycle-9 — CTF-Wiki ret2libc1 / Stack Binary-Fact Truth

状态：ACCEPTED（2026-09-06）

Domain：`stack / control_flow`

Train case：`stack_rop-pwn-linux-user-mode-stackoverflow-ret2libc-ret2libc1-c5603c89`

来源：CTF-Wiki `ctf-challenges`，`pwn/linux/user-mode/stackoverflow/ret2libc/ret2libc1`

Truth：`truth-d0c63d89c15d998d`

## Cycle 纪律

本轮遵守 `GENERAL_PWN_TRAINING_PROTOCOL.md`：

1. 在任何本题 PwnCraft feedback 之前，将 case 唯一登记到 `train`；
2. Phase A 只读取 manifest / source / solution EXP，并锁定 `expected_truth.json`；
3. 锁定后才检查当前 Stack adapter；
4. 只修本轮最早的 applicable divergence；
5. patch 不含 challenge name、binary hash、固定地址或题目专用分支。

## Clean-room truth 摘要

题目源码可直接证明：

- `main` 中存在 `char buf1[100]`；
- `gets(buf1)` 对该局部缓冲区执行无长度限制输入，因此 stack-overflow condition 为 source-proven；
- source 中存在全局字符串 `/bin/sh`，并引用 `system`。

可信 solution EXP 可证明 EXP 自身的布局：

- 第一个后续 word 之前有 `112` bytes payload prefix；
- 后续表达式依次为 `system_plt`、4-byte filler、`binsh_addr`。

但本轮没有独立执行 binary，因此以下事实保持 UNKNOWN / 非 runtime truth：

- PIE / NX / Canary / RELRO；
- 实际 EIP 覆盖观测；
- EXP 中固定地址的独立反汇编确认；
- glibc/libc base。

尤其：EXP 的 `112` 布局可以作为 `EXP_SUPPORTED` saved-IP relation，但不能冒充 `OBSERVED_RUNTIME` EIP control。

## FIRST DIVERGENCE

`BINARY_FACTS / PIE truth state`

Clean-room expected：

```text
bits = 32
PIE  = UNKNOWN
```

Cycle-8 Stack adapter 的旧调用路径：

```python
pie=bool(kwargs.get("pie"))
```

当调用方根本没有提供 PIE 事实时，`kwargs.get("pie")` 为 `None`，随后被 `bool(None)` 静默转换成 `False`；`run_stack()` 又把它发布为：

```text
BINARY_FACTS MATCH · bits=32, pie=False
```

这违反 Deterministic-First 的核心不变量：

```text
UNKNOWN != FALSE
```

这是本轮最早可确认的事实层偏差，因此停止向下挑选 ret2libc/ROP 更深层问题，不顺手修 payload/control-flow 识别。

## ROOT CAUSE

Stack domain adapter 使用二态 `bool` 表示实际上需要三态的保护事实：

```text
True     = 已知 PIE ON
False    = 已知 PIE OFF
None     = 当前证据不足 / UNKNOWN
```

入口处的 `bool(kwargs.get("pie"))` 抹掉了第三种状态，使“没有证据”变成“证明关闭”。

## PATCH

`autocorrect/domain_adapters.py`：

- `run_stack(..., pie: bool | None = None)`；
- `run_domain()` 区分“参数缺失/None”和显式 `False`；
- 新增 `_stack_binary_facts()`，输出 JSON-safe tri-state projection；
- `pie=None` 时发布 `pie: null`、`unknown_fields: ["pie"]`、provenance=`UNKNOWN`；
- `BINARY_FACTS.detail` 显式显示 `pie=UNKNOWN`；
- 只有显式 `pie=True` 才开启现有 Auditor 的 PIE 专属 hardcode 规则；UNKNOWN 仅关闭该规则开关，不会被写回为 `PIE=OFF`。

没有修改 Heap allocator、runtime saved-IP 判定、EXP payload 解析或 Electron UI。

## WHY GENERIC

修复只依赖事实状态，不依赖题目身份：

```text
missing fact -> UNKNOWN
explicit false -> False
explicit true -> True
```

因此适用于任何 Stack challenge、任何来源题库以及后续 BinaryFacts provider；不包含 ret2libc1 名称、hash、地址或 CTF-Wiki 特判。

## TESTS

新增 synthetic regression：

`autocorrect/tests/test_stack_binary_truth_tristate.py`

覆盖：

- PIE 参数缺失 → `None / UNKNOWN`；
- 显式 `False` 保持 False；
- 显式 `True` 保持 True。

新增真实 train-case regression：

`autocorrect/tests/test_cycle9_ret2libc1_training_case.py`

验证：

- intake gate 确认该题属于唯一 `train` split；
- material/domain 为 Stack x86；
- 真实 solution EXP 可进入 Stack adapter；
- 在没有独立 PIE evidence 时，真实题的 `BINARY_FACTS.pie` 保持 `None/UNKNOWN`，不再伪造 False。

## REGRESSION

GitHub Actions `Recognizer training gate` run #85，head：

`c5650496e15dcff09eab4793eed4291107666f4b`

结果：SUCCESS。

- project regression：`493 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`34 passed`；
- accepted truth regression：
  - lab13：`MATCH`；
  - note2：`MATCH`；
- gate：`failed=False -> exit 0`。

## CURRENT CASE RESULT

本轮 first divergence 已闭合：

```text
BEFORE: omitted PIE evidence -> False -> BINARY_FACTS MATCH as pie=False
AFTER : omitted PIE evidence -> None  -> BINARY_FACTS MATCH with pie=UNKNOWN
```

这不是“把题做对了”的声明。当前只表示本题经过的最早 Stack binary-fact truth 层不再把缺失证据伪造成负事实。

## GENERALIZATION IMPACT

- 所有 Stack domain adapter 调用都获得同一 tri-state 语义；
- 显式已知 PIE True/False 的旧调用行为保持兼容；
- Heap accepted truth 零退化；
- runtime EIP/RIP control 的 Cycle-8 强证据规则不变。

## NEXT ACTION

Cycle-10 继续使用真实开源 train challenge，并从 ret2libc1 重新寻找新的 first divergence。

优先检查下一层：

```text
INPUT/EXP evidence
→ payload layout / packed word semantics
→ saved-IP relation
→ control-flow path
```

重点不是直接“识别 ret2libc”标签，而是验证 PwnCraft 是否能从 `flat([...])` 中结构化保留：

- 112-byte prefix；
- 32-bit word 序列；
- system target expression；
- return/filler slot；
- argument expression；
- 每项的 source span / provenance。

若这里出现偏差，Cycle-10 仍只修最早一项。之后再交错切换到 Format / Heap / 更复杂 Stack 题，并用 validation split 做泛化验证。
