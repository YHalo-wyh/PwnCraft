# cycle-16 — SCTF 2026 slang / Reviewed Compiler Liveness + Slot Reuse

状态：**ACCEPTED（compiler-liveness / slot-reuse sublayer）** · 2026-09-06

Domain：`memory_write -> control_flow -> type_confusion/compiler`

Train case：`memory_write-sctf-2026-slang-a31e8aa0`

来源：SycloverTeam 官方 `SCTF-2026` 仓库，`Pwn/slang`。

## 1. First divergence

Cycle-15 已经能从真实 outbound Slang 源码恢复：

```text
function signatures
-> typed parameters / locals
-> do/while membership
-> pwn(round, vec_slot)
-> forged_header := forge()
-> source order
```

但这些只属于 embedded source structure。PwnCraft 仍无法回答：

```text
目标编译器是否真的会忽略某些 use？
vec_slot 的有效 lifetime 在编译器眼里到哪里结束？
forged_header 为什么能复用 vec_slot 的 slot？
```

因此本轮 first divergence 是 **compiler liveness / slot allocation semantics 缺失**，而不是直接从 `vec`/`str` 两种类型推断 type confusion。

## 2. Clean-room official truth

官方 writeup blob：

`f6d4a55258e8cd64fe31565eb3ce8fa7de7b1ab9`

官方 embedded Slang blob：

`7b7bd122aef50d6bc2a27218a48f4107d0a51d1f`

官方 writeup明确给出漏洞逻辑位于 `alloc_scan_stmt()`：

```c
} else if (s->kind == S_CALL) {
    Proto *p = find_proto(s->name);
    if (!(in_loop && p && p->ret == TY_VOID)) {
        for (int i = 0; i < s->nargs; i++) {
            alloc_scan_expr(ctx, s->args[i], at);
        }
    }
}
```

所以只有在：

```text
call is inside loop
AND callee return type == void
```

时，allocation liveness scan 才漏掉 call arguments。

官方题中：

```slang
do {
  pwn(round, vec_slot);
  forged_header := forge();
  keep_marker := one() + 1234;
  round := round + 1;
} while (round < 2);
```

而 `pwn(...) -> void`。因此 liveness scan 漏掉 `round` / `vec_slot` 在该调用中的 use。官方 writeup同时说明 codegen 仍会正常生成调用参数。

官方给出的近似生成 C 为：

```c
slot[0] = rt_vec_new(0);   // vec_slot
slot[1] = 0;               // round

do {
  F_pwn(slot[1], slot[0]);
  slot[0] = F_forge();     // forged_header reuses slot[0]
  slot[1] = slot[1] + 1;
} while (slot[1] < 2);
```

因此本轮锁定的 compiler truth 是：

```text
reviewed liveness rule
-> loop void-call argument omission
-> buggy effective live intervals
-> first-fit non-overlap slot allocation
-> vec_slot(vec) / forged_header(str) reuse slot 0
```

这仍不是 runtime type-confusion observation。

## 3. Generic patch

新增：

`pwncraft/pwncraft/features/audit/embedded_compiler.py`

核心原则：**compiler semantics 必须由显式 reviewed policy 提供，不能从 embedded source shape 猜。**

新增 `EmbeddedCompilerPolicy`：

```text
name
skip_loop_void_call_arguments_in_liveness
codegen_preserves_call_arguments
slot_allocator = first_fit_nonoverlap
provenance
```

当前只支持经过明确声明的 `first_fit_nonoverlap` slot allocator；未知 allocator policy 直接拒绝，不自行套用。

分析输出包括：

```text
lifetimes[]
  definition_orders
  effective_use_orders
  omitted_use_orders
  first_order / last_order

liveness_omissions[]
  callee / return type
  loop depth
  omitted variables
  codegen_preserves_arguments

slot_assignments[]
slot_reuse_relations[]
  from_variable / from_type
  to_variable / to_type
  slot
  cross_type
```

算法不包含 `slang`、`pwn`、`vec_slot`、`forged_header`、固定地址或题目 hash 特判。

## 4. Semantic pipeline integration

`semantic_facts.analyze_exp_semantics()` 新增可选参数：

```python
embedded_compiler_policy: EmbeddedCompilerPolicy | None = None
```

默认 `None` 时：

```text
Cycle-15 behavior preserved
embedded_programs exists
embedded_compiler_semantics = []
```

只有显式传入 reviewed policy 后才产生：

```text
embedded_compiler_semantics[]
provenance = EMBEDDED_STRUCTURE_PLUS_REVIEWED_COMPILER_POLICY
```

因此普通 embedded payload 不会因为“看起来像 compiler challenge”就被自动套入 SCTF 的编译器 bug。

## 5. Precision controls

本轮硬限制：

- 无 reviewed compiler policy，不产生 compiler-semantic fact；
- non-void loop call 不触发该 omission；
- 不因 cross-type slot reuse 自动宣称 type confusion；
- 不因 `scribble` 名字宣称 arbitrary write；
- 不把官方 writeup 当 GDB/runtime observation；
- 不从 slot reuse 直接跳到 GOT hijack / system；
- 不执行 Python wrapper、embedded DSL 或生成 ELF。

## 6. Truth revision

新增：

`autocorrect/cases/memory_write-sctf-2026-slang-a31e8aa0/expected_truth_cycle16.json`

Truth ID：

`truth-sctf2026-slang-compiler-liveness-slot-reuse-v3`

supersedes：

`truth-sctf2026-slang-embedded-structure-v2`

本轮 required sublayers：

```text
EMBEDDED_COMPILER_POLICY
LOOP_VOID_CALL_ARGUMENT_LIVENESS_OMISSION
EMBEDDED_LOCAL_LIFETIME
EMBEDDED_SLOT_REUSE
```

下一层 `runtime_type_confusion` / `derived_additive_write` 仍保留为 official-writeup truth、尚未自动 promotion。

## 7. Regression and one useful failure

新增 project regression：

`pwncraft/tests/test_embedded_compiler.py`

覆盖：

1. 无 policy 时绝不运行 compiler semantics；
2. loop + void callee 才能漏扫 arguments；
3. reviewed first-fit 能由 buggy lifetimes 重建 cross-type slot reuse；
4. non-void loop call 为负例；
5. 关闭 bug policy 后参数仍是 live use；
6. compiler fact 不自动变成 memory-write primitive。

新增 real-case regression：

`autocorrect/tests/test_cycle16_sctf2026_slang_compiler_semantics.py`

锁定官方 hashes、truth revision、`round/vec_slot` omission、slot 0 的 `vec -> str` reuse，同时断言 `primitives == []`。

首版 negative test 在 run `34044287521` 中失败：测试把 non-void `use(a)` 放在 `b := make_str()` **之前**，因此即使 `a` 的调用 use 被正确计入，两个真实 lifetime 仍然不重叠，first-fit 合法复用 slot 0。这个失败说明断言本身错误，不是模型漏掉 non-void use。

修正只调整 synthetic negative case 的源码顺序：先定义 `b`，再调用 `use(a)`，让两者在正确 liveness 下确实重叠；没有修改 production algorithm，也没有加题目特判。

## 8. Formal acceptance

最终 GitHub Actions `Recognizer training gate`：

- run：`34044380327`（#147）；
- HEAD：`9bfa3d84139c5b421ac4e44d1aaff6ed2ab3d13a`；
- project regression：`531 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`63 passed`；
- accepted heap truth：lab13 `MATCH`，note2 `MATCH`；
- `[truthregress-ci] failed=False -> exit 0`。

文档/调度状态提交后还需以最新 HEAD 的 workflow 再次通过为最终 repository-head acceptance。

## 9. What is NOT claimed

Cycle-16 不声明：

- 已动态观察 `slot[0]` runtime reuse；
- 已证明第二轮 loop 实际把 `str` 当 `vec` 使用；
- 已自动把 `forge()` 返回的 16 bytes 解成 `vec_t {data,size}`；
- 已自动证明 `scribble` 为 additive arbitrary write；
- 已自动规划 `puts@GOT -> system`；
- SCTF 2026 `slang` 整题已 MATCH。

## 10. Next first divergence

Cycle-17 的第一目标是把：

```text
reviewed slot reuse
+ loop iteration state
+ codegen-preserved pwn(round, vec_slot)
+ forged_header overwrites reused slot
```

组合成可审计的：

```text
second-iteration value flow
-> storage contains str value
-> consumed through source-level vec_slot argument
-> runtime type-confusion relation
```

只有完成这一步，下一轮才允许继续：

```text
forge() exact 16-byte return
-> vec_t field interpretation
-> data=0 / size=INT64_MAX
-> scribble index/delta semantics
-> constrained additive-write primitive
```

跨域队列继续保留 `CHAOS;HEAD`、`UBW/heapMage`、2026 国内 Stack/Format/Seccomp，以及 lab13 `PHYSICAL_MEMORY -> BINS`，避免 compiler lane 长期垄断训练。
