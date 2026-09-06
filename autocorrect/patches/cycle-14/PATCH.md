# cycle-14 — SCTF 2026 slang / Embedded Outbound Payload Truth

状态：**ACCEPTED（EXP transport sublayer）** · 2026-09-06

Domain：`memory_write -> control_flow -> type_confusion/compiler`

Train case：`memory_write-sctf-2026-slang-a31e8aa0`

来源：SycloverTeam 官方 `SCTF-2026` 仓库，`Pwn/slang`。

## 1. Domestic-first source selection

本轮按用户要求把选题策略调整为：

```text
2026 国内官方公开仓库
> 同质量海外官方仓库
> BUUCTF / CTF-Wiki 公开目录补覆盖与 validation
> 社区 archive validation-first
```

SCTF 2026 官方仓库当前公开 6 道 Pwn：

- `CHAOS;HEAD`
- `ParcelBridge Vault`
- `UBW`
- `heapMage`
- `kMage`
- `slang`

`slang` 提供官方 README、EXP、独立 `exploit.slang` 和 writeup，材料链足够完整，因此登记为 train。

## 2. Clean-room truth

官方 EXP 不是普通“Python payload 构造后打 ELF”的单层脚本，而是：

```text
Python wrapper
  -> multiline PAYLOAD (Slang source)
  -> source = PAYLOAD + "END_OF_SOURCE\n"
  -> source.encode()
  -> socket.sendall(...)
```

官方 writeup 进一步证明后续目标语义：

```text
compiler liveness omission
-> slot reuse
-> str/vec type confusion
-> forged vec(data=0, size=INT64_MAX)
-> scribble behaves as additive arbitrary write
-> puts@GOT adjusted to system
```

但 Cycle-14 只接收第一层“嵌入程序确实流向 outbound send”的 EXP truth；目标侧 type-confusion/write primitive 保留为下一 first divergence，不偷跑。

## 3. First divergence

PwnCraft 之前的 `ExploitIR` 能看到：

```python
sock.sendall(source.encode())
```

但 interaction 中只有表达式文本 `source.encode()`。

它无法静态回答：

```text
source 到底是不是确定字面量？
它是否来自 PAYLOAD？
END_OF_SOURCE 是否真的被拼进去？
实际发出的嵌套 DSL 源码是什么？
```

因此对于 compiler/VM/custom-protocol 题，Python wrapper 与真正攻击载荷之间存在证据断层。

## 4. Generic patch

新增：

`pwncraft/pwncraft/features/audit/outbound_payload.py`

支持窄而确定的静态值域：

- `str` / `bytes` literal assignment；
- 已知 literal 之间的 `+`；
- 已知 `str` 的 `.encode()`（默认或常量 encoding）；
- `send` / `sendall` / `sendline` 第一参数；
- module literal 可流入 entry function (`main/exp/pwn/solve/attack`)；
- 不执行用户代码。

输出 `OutboundLiteralPayload`：

```text
expression
content
content_kind
byte_length
sha256
line
scope
provenance = EXP_AST_LITERAL_DATAFLOW
```

并由 `analyze_exp_semantics()` 发布为：

```text
outbound_literal_payloads
```

## 5. Precision controls

以下情况不得 promotion：

```python
payload = input() + "END"
sock.sendall(payload.encode())
```

因为动态输入未知。

以下也不得 promotion：

```python
sock.sendall(PAYLOAD.encode(codec_name))
```

因为 encoding 动态未知。

同时：

- 看到 `scribble` 名字不能直接判 arbitrary write；
- 看到 `/bin/sh` / `puts` 不能直接判 GOT hijack；
- 当前不解析 Slang AST；
- 当前不把官方 writeup truth 冒充 GDB/runtime observation。

## 6. Real SCTF case

官方 wrapper blob：

`a31e8aa066aab023f58750923652f3f40fbbb874`

官方 embedded Slang blob：

`7b7bd122aef50d6bc2a27218a48f4107d0a51d1f`

官方 writeup blob：

`f6d4a55258e8cd64fe31565eb3ce8fa7de7b1ab9`

Truth lock：

`truth-sctf2026-slang-outbound-payload-v1`

当前 required sublayer：

```text
EXP_OUTBOUND_LITERAL_PAYLOAD
module literal -> local concat -> encode -> sendall
```

## 7. Tests

新增 project regression：

`pwncraft/tests/test_outbound_literal_payload.py`

覆盖：

1. module literal + terminator -> encode -> sendall；
2. dynamic input 不得 promotion；
3. dynamic encoding 不得 promotion；
4. direct literal bytes send；
5. semantic-facts 输出 payload 但不自动产生 memory-write primitive；
6. SCTF slang 真实 wrapper shape 恢复 `scribble(...)` 源码和 `END_OF_SOURCE`。

新增 training regression：

`autocorrect/tests/test_cycle14_sctf2026_slang_training_case.py`

验证 train split、官方材料 hashes、真实 wrapper transport 和“不偷升 target primitive”。

## 8. CI

核心实现与真实题 regression 在 GitHub Actions `Recognizer training gate` run `34041809904` 通过：

- project regression：`519 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`55 passed`；
- accepted heap truth：lab13 `MATCH`，note2 `MATCH`；
- gate：`failed=False -> exit 0`。

## 9. What is NOT claimed

本轮不声明：

- PwnCraft 已自动理解 Slang 语法；
- type confusion 已由 recognizer 自动识别；
- `scribble` 已自动证明 arbitrary write；
- puts@GOT -> system 已自动恢复；
- 生成 C/ELF 已被自动构建或动态执行；
- SCTF 2026 `slang` 整题已 MATCH。

## 10. Next first divergence

优先继续国内 2026 官方题库，并保持跨域交错：

1. `slang`：嵌入 DSL 的 call/data model -> type confusion -> additive write；
2. `CHAOS;HEAD`：对象生命周期/UAF -> leak -> adjacent function pointer -> setcontext/ROP；
3. `UBW` / `heapMage`：现代 glibc heap；
4. 国内 2026 Stack / Format String 新题若有更完整官方材料则可插队；
5. BUUCTF/CTF-Wiki 用于补足经典 pattern 与 validation，不再作为新题优先来源。
