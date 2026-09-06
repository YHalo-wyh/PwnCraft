# cycle-15 — SCTF 2026 slang / Embedded Typed Program Structure

状态：**ACCEPTED（embedded structure sublayer）** · 2026-09-06

Domain：`memory_write -> control_flow -> type_confusion/compiler`

Train case：`memory_write-sctf-2026-slang-a31e8aa0`

来源：SycloverTeam 官方 `SCTF-2026` 仓库，`Pwn/slang`。

## 1. First divergence

Cycle-14 已能确定：

```text
Python PAYLOAD literal
-> source = PAYLOAD + END_OF_SOURCE
-> source.encode()
-> socket.sendall(...)
-> exact outbound bytes
```

但 PwnCraft 仍把第二语言程序视为一块 opaque bytes，无法回答：

```text
有哪些 function？
参数/局部变量的源类型是什么？
哪些调用发生在 do/while 中？
调用和赋值的源码顺序是什么？
```

因此在进入 compiler liveness / slot reuse 之前，最早缺口是 embedded program 的结构真值，而不是直接宣称 type confusion。

## 2. Clean-room truth

官方 `exploit.slang` blob：

`7b7bd122aef50d6bc2a27218a48f4107d0a51d1f`

它明确包含：

```text
pwn(int round, vec forged_vec) -> void
main locals: int round, int keep_marker, vec vec_slot, str forged_header
```

并且 `main` 的同一个 `do ... while` body 中源码顺序为：

```text
pwn(round, vec_slot)
forged_header := forge()
keep_marker := one() + 1234
round := round + 1
```

`pwn` 中还存在：

```text
scribble(forged_vec, 526339, -205200)
```

这些是 embedded source structure；它们本身仍不能证明编译器运行时把 `vec_slot` 与 `forged_header` 分到同一 slot。

## 3. Generic patch

新增：

`pwncraft/pwncraft/features/audit/embedded_program.py`

实现一个窄而确定的 `typed_function_dsl` 结构解析层，支持：

- `function name(type arg, ...) : type local, ... -> rettype {`；
- typed parameters / locals；
- `name := expression;` assignment；
- direct `callee(arg, ...);` call；
- assignment RHS 为 direct call 时保留 callee/arguments；
- `do { ... } while (...)` 的 loop depth；
- statement source line + deterministic order；
- nested argument comma splitting，不执行 embedded code。

`semantic_facts.analyze_exp_semantics()` 只对已经由 Cycle-14 证明真正流向 outbound send 的 literal payload 尝试结构解析，发布：

```text
embedded_programs[]
  syntax_family
  functions[]
    parameters
    locals
    statements
      kind / target / expression / callee / arguments
      line / order / loop_depth
  source_payload_sha256
  provenance = OUTBOUND_LITERAL_EMBEDDED_STRUCTURE
```

因此不是扫描任意 Python 字符串后随便猜 DSL。

## 4. Precision controls

本轮继续禁止以下 shortcut：

- 不因 `vec` 和 `str` 两种类型同时出现就判 type confusion；
- 不因函数名叫 `scribble` 就判 arbitrary write；
- 不因 payload 包含 `puts` / `/bin/sh` 就判 GOT hijack；
- 不执行 Python wrapper；
- 不执行 embedded DSL；
- 非 UTF-8 或不匹配 typed-function header 的 outbound 数据保持无 embedded-program fact；
- compiler liveness / slot allocator 行为仍为独立下一层。

## 5. Truth revision

Cycle-14 truth 保持不修改；新增：

`expected_truth_cycle15.json`

Truth ID：

`truth-sctf2026-slang-embedded-structure-v2`

它 supersedes：

`truth-sctf2026-slang-outbound-payload-v1`

本轮 required sublayers：

```text
EXP_OUTBOUND_LITERAL_PAYLOAD
EMBEDDED_TYPED_FUNCTION_STRUCTURE
EMBEDDED_LOOP_ORDER
```

## 6. Regression

新增 project regression：

`pwncraft/tests/test_embedded_program.py`

覆盖：

1. typed function parameter/local preservation；
2. do/while membership + statement order；
3. direct call argument structure；
4. assignment-RHS direct call；
5. malformed/non-UTF8 negative cases；
6. 只有 proven outbound literal 才进入 embedded structure pipeline；
7. structure fact 不自动产生 memory-write primitive。

新增 training regression：

`autocorrect/tests/test_cycle15_sctf2026_slang_embedded_structure.py`

锁定官方 SCTF source shape、truth revision、loop order 和 `scribble` call shape，同时断言 slot alias / arbitrary write 尚未偷升。

## 7. CI

核心实现与真实题 regression 在 GitHub Actions `Recognizer training gate` run `34043261318` 通过：

- project regression：`525 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`59 passed`；
- accepted heap truth：lab13 `MATCH`，note2 `MATCH`；
- gate：`failed=False -> exit 0`。

## 8. What is NOT claimed

本轮不声明：

- 已自动识别 compiler liveness bug；
- 已自动恢复 slot allocation；
- 已证明 `vec_slot` / `forged_header` runtime alias；
- 已证明 `scribble` 是任意地址加减写；
- 已自动得到 puts@GOT -> system exploit plan；
- SCTF 2026 `slang` 整题已 MATCH。

## 9. Next first divergence

Cycle-16 优先仍使用 SCTF 2026 官方材料，进入真正的 compiler semantics：

```text
embedded typed source
-> compiler liveness rule evidence
-> do/while void-call argument omission
-> slot lifetime intervals
-> slot reuse relation
-> type confusion
```

只有这层被证明后，下一层才允许把 forged vec 的 `data/size` 解释和 `scribble` 写语义组合成 constrained additive-write primitive。

跨域队列仍保留：

- `CHAOS;HEAD`：object lifetime/UAF -> leak -> adjacent function pointer；
- `UBW` / `heapMage`：现代 glibc heap；
- 2026 国内 Stack / Format / Seccomp 新题可按材料质量插队；
- lab13 `PHYSICAL_MEMORY -> BINS` 后续继续推进。
