# cycle-17 — SCTF 2026 slang / Cross-Iteration Value Flow + Static Type-Confusion Relation

状态：**ACCEPTED（cross-iteration value-flow / type-confusion relation sublayer）** · 2026-09-07

Domain：`memory_write -> control_flow -> type_confusion/compiler`

Train case：`memory_write-sctf-2026-slang-a31e8aa0`

来源：SycloverTeam 官方 `SCTF-2026` 仓库，`Pwn/slang`。

## 1. First divergence

Cycle-16 已经锁定：

```text
reviewed compiler policy
-> loop void-call argument omission
-> buggy effective lifetime
-> first-fit non-overlap slot allocation
-> vec_slot(vec) / forged_header(str) reuse slot 0
```

但 slot reuse 仍不等价于 type confusion。缺失的是执行顺序层面的确定性关系：

```text
第一轮 pwn(round, vec_slot)
-> forged_header := forge() 写入复用 slot
-> loop backedge
-> 是否一定存在第二轮？
-> 第二轮进入 pwn 前 slot 是否仍保存 forged_header？
-> codegen 是否仍通过 vec_slot 参数消费这个 slot？
```

因此本轮只补 **cross-iteration value flow**，不越级解释 `forge()` 的 16 字节布局，也不从 `scribble` 名称猜 arbitrary write。

## 2. Locked truth

新增：

`autocorrect/cases/memory_write-sctf-2026-slang-a31e8aa0/expected_truth_cycle17.json`

Truth ID：

`truth-sctf2026-slang-cross-iteration-type-confusion-v4`

supersedes：

`truth-sctf2026-slang-compiler-liveness-slot-reuse-v3`

官方 embedded source 给出：

```slang
round := 0;
...
do {
  pwn(round, vec_slot);
  forged_header := forge();
  ...
  round := round + 1;
} while (round < 2);
```

结合 Cycle-16 已审核的 compiler policy：

```text
vec_slot / forged_header share slot 0
AND pwn(...) arguments are emitted by codegen
```

本轮能够确定性推出：

```text
round=0
-> first iteration
-> round=1
-> 1 < 2 == true
-> second iteration exists

first iteration pwn consumes slot 0
-> forged_header writes slot 0 afterwards
-> no same-slot write occurs before backedge
-> second iteration reaches pwn before any slot-0 refresh
-> resident str value is consumed through source-level vec_slot(vec)
```

这形成 `runtime_type_confusion` **relation**，但状态明确为 `derived_static`，`runtime_observed=false`。

## 3. Generic patch

新增：

`pwncraft/pwncraft/features/audit/embedded_execution.py`

它位于 embedded source structure 与 reviewed compiler semantics 之后，只接受已存在的结构/slot facts，不重新猜编译器行为。

当前能力：

- 从支持的 `do { ... } while (...)` 恢复 loop range；
- 对一个很小、确定性的整数表达式子集做静态求值；
- 恢复 first-iteration 前后整数状态；
- 只有条件求值结果严格为 `True` 时才声明第二轮存在；
- `False` 阻断 promotion；
- 无法求值返回 unknown，不猜；
- 将 reviewed cross-type slot reuse 与 loop body statement order 对齐；
- 检查 producer 写入后到 loop backedge 是否还有同 slot overwrite；
- 检查下一轮 consumer call 之前是否存在同 slot refresh；
- 只有 codegen policy 明确保留被漏扫的 call argument 时才建立消费关系。

输出包括：

```text
do_while_iteration_state
cross_iteration_slot_value_flow
runtime_type_confusion
```

其中 type-confusion fact 仍不是 memory-write primitive。

## 4. Semantic pipeline

`semantic_facts.analyze_exp_semantics()` 新增输出：

```text
embedded_execution_semantics[]
```

调用链现在为：

```text
outbound literal payload
-> embedded program structure
-> reviewed compiler semantics
-> deterministic cross-iteration execution semantics
```

没有 `EmbeddedCompilerPolicy` 时：

```text
embedded_compiler_semantics = []
embedded_execution_semantics = []
```

因此普通 DSL payload 不会被自动套入 SCTF slang 的 compiler bug。

## 5. Precision controls

本轮硬限制：

- loop condition 无法静态求值时保持 unknown；
- 第一轮后 condition 为 false 时不得声称第二轮消费；
- reused slot 在下一轮 consumer 之前被 refresh 时不得声称旧 resident value 被消费；
- producer 之后到 backedge 若有同 slot overwrite，阻断该 value-flow；
- 必须存在 reviewed cross-type slot-reuse relation；
- 必须存在对应 liveness omission，且 policy 明确 `codegen_preserves_call_arguments=true`；
- 静态推导不得伪装成 GDB/runtime observation；
- type confusion 不自动发布成 arbitrary/additive write primitive；
- 不执行 Python wrapper、embedded DSL 或生成目标 ELF。

## 6. Regression

新增 project regression：

`pwncraft/tests/test_embedded_execution.py`

覆盖：

1. 可证明第二轮 + reviewed slot reuse -> cross-iteration value flow；
2. 单轮 loop 不 promotion；
3. opaque/unknown loop progression 保持 unknown；
4. 下一轮 consumer 前刷新 reused slot 阻断 stale-value claim；
5. 无 reviewed compiler policy 时 execution semantics 为空；
6. type confusion 仍不进入 `primitives`。

新增 real-case regression：

`autocorrect/tests/test_cycle17_sctf2026_slang_cross_iteration_type_confusion.py`

锁定：

```text
round 0 -> 1
round < 2 == true
slot 0
forged_header(str) -> vec_slot(vec)
second iteration pwn consumer
runtime_observed == false
primitives == []
```

## 7. One useful failure

首版 synthetic positive regression 在 run `34045374504` 失败：

```text
expected first flow producer: forged_header
actual first flow producer: round
```

不是 production analyzer 错，而是 synthetic fixture 比官方题少了：

```slang
keep_vec(vec_slot);
```

这改变了真实 lifetime geometry，使 first-fit 合法产生额外的 `vec_slot -> round` slot reuse。测试还错误依赖 `cross_iteration_value_flows[0]` 的顺序。

修正方式：

- synthetic case 恢复 `keep_vec(vec_slot)`，使其与要测试的 lifetime 关系一致；
- assertion 按 `producer_variable/consumer_variable` 选择目标 relation，不依赖 list 顺序；
- refresh negative 只断言目标 `forged_header -> vec_slot` relation 不存在，而不是禁止其他合法 relation。

**没有为了过测试修改 production inference。**

## 8. Acceptance

修正后 GitHub Actions `Recognizer training gate`：

- run：`34045451968`（#157）；
- HEAD：`d23ad34beff9d25e86c6e2683db242131e88e362`；
- project regression：`536 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`67 passed`；
- accepted heap truth：lab13 `MATCH`，note2 `MATCH`；
- `[truthregress-ci] failed=False -> exit 0`。

Scheduler/documentation 收尾提交后仍需以最新 branch HEAD 的 workflow 为最终 cycle-17 branch acceptance；合入 main 后再以 main workflow 作为 repository-head acceptance。

## 9. What is NOT claimed

Cycle-17 不声明：

- 已动态观察 slot 0 的 runtime 内容；
- 已自动将 `forge()` 返回的 16 bytes 解码成目标 `vec` 布局；
- 已自动证明 `data=0 / size=INT64_MAX`；
- 已自动解释 `scribble` 的 index/delta 内存语义；
- 已产生 arbitrary/additive write primitive；
- 已规划 `puts@GOT -> system`；
- SCTF 2026 `slang` 整题已闭环。

## 10. Next first divergence

Cycle-18 允许继续：

```text
exact forge return bytes
-> reviewed target vec representation
-> data / size field interpretation
-> scribble bounds/index/delta semantics
-> constrained additive 64-bit write
```

仍然要求 target representation/operation semantics 有明确来源；不能仅凭 16 字节形状或 `scribble` 名称脑补。

跨域队列继续保留 `CHAOS;HEAD`、`UBW/heapMage`、2026 国内 Stack/Format/Control Flow，以及 lab13 `PHYSICAL_MEMORY -> BINS`，避免 compiler lane 无限连刷。
