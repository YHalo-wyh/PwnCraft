# cycle-18 — SCTF 2026 slang / Reviewed Runtime Layout + Constrained Additive Write

状态：**ACCEPTED（forged-object / indexed-additive-write sublayer）** · 2026-09-07

Domain：`memory_write -> control_flow -> type_confusion/compiler/runtime`

Train case：`memory_write-sctf-2026-slang-a31e8aa0`

来源：SycloverTeam 官方 `SCTF-2026` 仓库，`Pwn/slang`。

## 1. First divergence

Cycle-17 已经能够确定：

```text
reviewed compiler liveness omission
-> vec_slot / forged_header slot reuse
-> deterministic second iteration
-> resident forged_header(str) consumed through vec_slot(vec)
-> static type-confusion relation
```

但 type confusion 本身仍不能推出内存写。缺失的是三个独立事实：

```text
forge() 到底返回哪些字节？
目标 runtime 的 vec 物理布局是什么？
scribble(vec, index, delta) 对内存的真实语义是什么？
```

因此本轮只补 **reviewed runtime semantics**，不把官方 writeup 的最终 GOT 劫持直接塞进 primitive 层。

## 2. Clean-room truth

官方 `exploit.slang` blob：

`7b7bd122aef50d6bc2a27218a48f4107d0a51d1f`

其中 `forge()` 精确返回：

```text
00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff 7f
```

官方 writeup blob：

`f6d4a55258e8cd64fe31565eb3ce8fa7de7b1ab9`

给出 runtime `vec_t`：

```c
typedef struct vec_t {
    int64_t *data;
    int64_t size;
} vec_t;
```

以及 `scribble(forged_vec, idx, delta)` 的等价语义：

```c
*(int64_t *)(data + idx * 8) += delta;
```

对官方 payload：

```text
forge bytes
-> little-endian vec.data = 0
-> vec.size = 0x7fffffffffffffff

scribble(forged_vec, 526339, -205200)
-> 0 <= 526339 < INT64_MAX
-> address = 0 + 526339 * 8
-> address = 0x404018
-> *(int64_t *)0x404018 += -205200
```

本轮因此可以锁定：

```text
constrained additive 64-bit write
```

但不能自动升级为：

```text
arbitrary write
puts@GOT identified
puts -> system control plan
runtime exploit success
```

## 3. Generic patch

新增：

`pwncraft/pwncraft/features/audit/embedded_runtime.py`

引入显式 reviewed runtime policy：

- `EmbeddedFieldLayout`
- `EmbeddedObjectLayout`
- `EmbeddedIndexedAddSemantics`
- `EmbeddedRuntimePolicy`

runtime 层严格位于 Cycle-17 execution/type-confusion 层之后。

推导前置条件：

1. 已存在 `derived_static` type-confusion relation；
2. producer 必须是可精确解析的常量返回值；
3. 返回字节长度必须和 reviewed object layout 精确一致；
4. field offset/width/endianness 必须来自 reviewed policy；
5. indexed-add builtin 必须来自 reviewed runtime policy；
6. confused object 参数绑定必须唯一；
7. index / delta 必须静态可求值；
8. 简单 early-return 条件必须能证明第二轮 call 可达；
9. bounds 必须可证明；
10. 计算地址必须落在目标 pointer width 内。

任何一项未知都不发布 write primitive。

## 4. Semantic pipeline

Cycle-18 后 slang 的自动事实链为：

```text
Python wrapper
-> exact outbound Slang source
-> typed embedded program
-> reviewed compiler liveness/slot reuse
-> deterministic second-iteration resident-value flow
-> str-as-vec type confusion
-> exact forge return bytes
-> reviewed vec field interpretation
-> reviewed scribble indexed-add semantics
-> exact index/delta/bounds/address
-> constrained additive 64-bit write
```

`semantic_facts.analyze_exp_semantics()` 新增：

```text
embedded_runtime_policy
embedded_runtime_semantics
```

runtime policy 单独存在时不会执行；没有 compiler/type-confusion 上游证明时仍输出空 runtime facts。

## 5. Precision controls / negative cases

项目回归新增以下反例：

- 无 runtime policy：type confusion 不得升级成 write；
- 只有 runtime policy、无 compiler policy：不得绕过 type-confusion proof；
- forged producer 长度与 object layout 不一致：不得解释字段；
- delta 未知：不得发布 write；
- index 越界：不得发布 write；
- static early-return/reachability 无法证明：保持 unknown；
- primitive 名称只允许 `constrained additive 64-bit write`，不得称 `arbitrary write`。

## 6. Useful failure during regression

首次 synthetic regression 失败不是生产规则错误，而是测试夹具把字符串引号错误地一起转义，导致 `forge()` 返回表达式不再是合法常量字符串。

同时一条测试断言把 limitation 中明确写着 `not labeled arbitrary write` 的文本也当成了“错误包含 arbitrary write”。

修正方式：

- 修复 synthetic literal，使其与真实 embedded source 的字符串语法一致；
- 断言 primitive 的 **name/state** 不得升级，而不是禁止 limitation 文本解释该边界；
- 未放宽 runtime inference。

随后项目回归恢复成功。

真实题 regression 还发现 Cycle-17 的 wrapper escaping 只适合结构解析，不适合 Cycle-18 的精确 byte decoding；因此改为先保存 exact `OFFICIAL_SLANG`，再用 Python `repr()` 构造 transport wrapper。这样 outbound extractor 看到的仍是官方 exact Slang bytes。

## 7. Regression / acceptance

Branch：`training/cycle-18`

关键成功 gate：

```text
GitHub Actions run 34078591346
HEAD 2e0eb7bff0e2f12df2f1f6c8c364ea2db77cc192
Recognizer training gate: SUCCESS
```

该 run 覆盖：

- Project regression
- Training infrastructure regression
- Accepted truth regression

全部成功。

Truth revision：

```text
truth-sctf2026-slang-forged-vec-additive-write-v5
```

supersedes：

```text
truth-sctf2026-slang-cross-iteration-type-confusion-v4
```

## 8. What is NOT claimed

Cycle-18 明确不声称：

- `0x404018` 已自动识别为 `puts@GOT`；
- 非 PIE / relocation / GOT 可写性已经自动组合；
- `-205200` 已自动解释为 `system - puts` 的目标差值；
- 自动生成最终 control-flow takeover plan；
- GDB/pwndbg runtime memory observation；
- 远程 shell / exploit success。

## 9. Next first divergence

Cycle-19 的 first divergence 已收窄为：

```text
proven additive write at 0x404018
+ target binary symbol/relocation identity
+ non-PIE / GOT mutability evidence
+ exact desired symbol delta
-> reviewed exploit control plan
```

仍然先证明 target identity 和约束，再决定能否得到：

```text
puts@GOT += (system - puts)
```

即使该控制计划成立，也不得把静态计划冒充远程执行成功。
