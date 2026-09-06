# cycle-11 — Cyber Apocalypse 2026 / FILE-FSOP EXP Intent Truth

状态：**ACCEPTED（EXP semantic layer） / FULL TARGET TRUTH NOT CLAIMED** · 2026-09-06

Domain：`io_file / leak / control_flow`

Train case：`io_file-htb-cyber-apocalypse-2026-the-emptiness-machine-exp-32b6c777`

Truth：`truth-ccbd3b4843d2ab79`

## 1. Latest-first 选题策略

本轮开始把真实题 curriculum 改为：

```text
latest-first
  + evidence-gated
  + split-before-observe
```

先看最新 CTFtime 赛事，再按材料质量决定能否进入 train。更新不代表可以降低真值门槛。

本轮检索到 2026-08-29/30 的 ASIS CTF Quals 2026 与 COMPFEST CTF 2026。ASIS 有参与者公开的 binary + exploit + writeup，适合后续 validation-first；COMPFEST 本轮没有解析到可直接进入 PwnCraft 的 source-rich Pwn 材料。

最终用于本轮 train patch 的是 Hack The Box 官方 `cyber-apocalypse-ctf-2026` 仓库中的 `The Emptiness Machine`：来源可信，官方 writeup 与 solver 同时公开，足够建立一个严格收窄的 EXP-semantics truth。

候选队列见：`latest_case_candidates.json`。

## 2. Clean-room scope

官方 solver 中可直接观察到这些符号引用：

```text
libc.sym._IO_2_1_stdout_
libc.sym._IO_2_1_stderr_
libc.sym._IO_wfile_jumps
libc.sym.system
```

以及：

```python
libc.address = u64(r.recv(8)) - libc.sym._IO_2_1_stdout_ - 132
```

因此本轮能锁定的是：

```text
EXP names a libc FILE object
+ EXP names an _IO_*_jumps vtable
=> FSOP / FILE corruption intent is EXP_SUPPORTED
```

不能由此升级为：

```text
target FILE corruption primitive proven
runtime reachability proven
exploit success observed
```

## 3. 本轮 first divergence

PwnCraft 之前虽然有 `io_file` domain，但 EXP Live Auditor 没有结构化记录：

```text
libc.sym.<symbol>
elf.sym.<symbol>
```

因此一个明显使用 `_IO_2_1_stderr_` + `_IO_wfile_jumps` 的真实 EXP，在进入 Workspace 前会丢失 FILE/FSOP intent。

另一个真值问题是：旧 `pwn_surface` 只按 primitive 名字判断 IO_FILE，完全忽略 primitive 的 `state`。如果直接把 EXP-derived intent 写成 primitive，UI 会把“EXP 意图”错误升级成 `evidenced`。

## 4. Generic patch

### 4.1 ExploitIR SymbolRef

新增 `SymbolRef`：

```text
expression
namespace
symbol
line
scope
```

`extract.py` 现在识别：

```python
libc.sym.system
libc.sym['_IO_2_1_stderr_']
elf.sym.main
```

只记录源码引用，不解析地址、不验证符号存在、不判断可达性。

### 4.2 EXP semantic facts

新增：

`pwncraft/pwncraft/features/audit/semantic_facts.py`

FSOP intent 的通用最小规则：

```text
at least one _IO_2_1_* symbol reference
AND
at least one _IO_*_jumps symbol reference
```

满足后写入：

```text
name   = FSOP / FILE corruption intent
state  = derived
source = exp-ast
```

看到 `system` 一项、看到一个 FILE object、只看到一个 vtable，都不会单独判 FSOP。

### 4.3 Truth-aware IO_FILE surface

`pwn_surface.py` 现在区分 primitive state：

```text
derived / inferred / candidate / intent
=> io_file = partial

confirmed / observed / proven / validated
=> io_file = evidenced
```

历史 primitive 没有 state 时继续按 `confirmed` 兼容。

这避免把 EXP 的利用意图冒充目标/运行时真值。

### 4.4 Per-case material contract

修复 `case_manifest.py` 中一个此前“注释说支持、代码实际没支持”的问题：

`evaluation_contract.required_materials`

现在真正生效，且只允许：

```text
binary / exp / source / libc
```

未知材料名直接报错，不能利用自定义字符串绕过 gate。

同时修正：

```text
technique=fsop
fmt -> io_file
```

默认 IO_FILE 仍要求 `binary + exp`。只有 manifest 明确声明 EXP-only evaluation scope 时，才能把 `required_materials` 收窄成 `exp`；claims_allowed / claims_forbidden 必须一起写清楚。

## 5. 一个刻意保留的 UNKNOWN

官方 solver 使用：

```python
u64(r.recv(8))
```

`recv(8)` 与 `recvn(8)` 不同，AST 不能证明返回值一定正好 8 bytes。

因此 Cycle-10 加入的 exact-width 规则在这里没有被“训练坏”：

```text
u64(r.recv(8))
=> EXP_LEAK_003 remains
```

这条 suggestion 是合理不确定性，不能为了让真题变绿而抹掉。

## 6. Tests

新增：

- `pwncraft/tests/test_exp_io_file_semantics.py`
- `autocorrect/tests/test_cycle11_htb_ca2026_emptiness_training_case.py`

覆盖：

- dot/subscript 两种 ELF.sym 引用；
- FILE object + IO vtable -> derived FSOP intent；
- 单个符号不误判；
- derived intent 在 Pwn Surface 只能是 partial；
- confirmed runtime/target primitive 才能升级 evidenced；
- EXP parse failure 不产生 semantic primitive；
- 新 case 唯一 split=train；
- EXP-only material contract 可执行；
- `recv(8)` 继续保留未知长度提醒。

## 7. Regression

GitHub Actions `Recognizer training gate` run #104，head：

`6293720afd3e52b56e6dd64ba0eeaf5407076312`

结果：SUCCESS。

```text
project regression:
502 passed, 1 skipped, 6 subtests passed

autocorrect regression:
40 passed

accepted truth regression:
lab13 -> MATCH
note2 -> MATCH
failed=False -> exit 0
```

## 8. What is NOT claimed

本轮不声明：

- `The Emptiness Machine` 整题已经被 PwnCraft 静态识别闭环；
- target binary 已独立验证；
- `_IO_FILE` corruption 已被 runtime observed；
- libc base 已实际泄露；
- `system` 控制流已经成功触发。

本轮只接受 **EXP semantic layer**。

## 9. 下一轮

优先级按“新鲜度 × 材料可信度 × 能补 PwnCraft 缺口”排序：

1. **ASIS CTF Quals 2026 / arena-snapshots**：2026-08-29/30，binary + exploit + participant writeup 齐全；先 validation-first，重点验证 custom allocator / metadata-payload desync / type confusion，避免 PwnCraft 把所有 heap 题都硬套 glibc。
2. **SekaiCTF 2026 / echo-chamber**：官方 source-rich，适合 `signedness -> allocation length -> read length -> memory impact`，是更强的 deterministic train case。

新的硬约束已经写入 `pwn_scope.json`：**未知 allocator family 不允许自动使用 glibc chunk/bin 语义。**
