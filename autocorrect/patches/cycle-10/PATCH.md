# cycle-10 — StarCTF 2018 note / Inline Leak-Width Truth

状态：**ACCEPTED（通用子层修复） / FULL CASE MATERIAL-BLOCKED** · 2026-09-06

Domain：`stack / leak / control_flow`

Train case：`stack_rop-pwn-linux-user-mode-stackoverflow-fake_frame-StarCTF2018-not-97cad9a0`

来源：StarCTF 2018 `note`，当前训练材料来自 CTF-Wiki curator archive。

Truth：`truth-e69e8305bc975376`

## 1. 本轮为何换题

Cycle-9 使用 CTF-Wiki `ret2libc1`。Cycle-10 按跨比赛/跨形状训练策略切换到 StarCTF 2018 `note`，避免连续针对同一种 ret2libc1 payload 写法做局部拟合。

本轮只处理真实 EXP 中一条可独立证明的 leak-input 语义，不把整个题目的结果外推为 MATCH。

## 2. Clean-room truth

真实归档 EXP 中存在：

```python
libc.address = u64(io.recvn(6) + '\0\0') - libc.sym['puts']
```

仅由该源码表达式即可确定：

```text
recvn(6)          -> 精确 6 bytes
'\0\0'           -> 2 bytes padding
concatenation     -> 精确 8 bytes
u64 required      -> 8 bytes
```

因此该 `u64(...)` 输入在 EXP 语义层不是 short read，也不是 unknown-length input。

这只证明 EXP 的输入宽度与基址计算意图，不把远程泄漏值、libc base 或 RIP 控制冒充本轮 runtime observation。

## 3. 首次真实材料运行暴露的 material defect

第一次把完整归档 EXP 接入 Cycle-10 regression 时，GitHub Actions run #91 失败。失败不是新规则本身，而是归档 EXP 第 11 行：

```python
remoteAddr = 47.89.18.224
```

该 IPv4 地址没有引号，因此对 Python AST 是真实 `SyntaxError`。

PwnCraft 在这里返回 `EXP_PARSE` 是正确行为。根据 Deterministic-First，本轮没有：

- 静默把 IP 加引号；
- 改写原始 challenge solution；
- 假装整份 EXP 可以执行；
- 绕过 parse failure 后宣称整题 MATCH。

最终 regression 明确保留这个 upstream defect，同时从原始文件中逐字抽取 leak RHS 作为 source-derived subcase 来验证本轮通用规则。

因此当前状态是：

```text
FULL STARCTF CASE: MATERIAL-BLOCKED at EXP_PARSE
LEAK INPUT SUBLAYER: ACCEPTED
```

## 4. 本轮 first divergence

在可独立解析的真实 leak 表达式上，旧 ExploitIR 只会追踪类似：

```python
leak = io.recv(6)
u64(leak)
```

这种“变量名 -> recv 长度”数据流。

对于：

```python
u64(io.recvn(6) + '\0\0')
```

旧实现没有把 inline AST 的精确宽度传给 leak rules，于是下游把长度当成 UNKNOWN，并可能产生错误的 `EXP_LEAK_003` suggestion。

这违反：

```text
可由 AST 精确证明的事实 != UNKNOWN
```

## 5. Root cause

`extract.py::_link_leak()` 的事实来源只有变量接收表：

```text
var_recv_length / var_recv_unknown
```

没有 expression-level byte-width evaluator。

因此 direct call、padding concatenation 等可精确求值的组合表达式丢失了宽度事实。

## 6. Generic patch

修改 `pwncraft/pwncraft/features/audit/extract.py`，增加窄而确定性的 byte-width 推导：

- bytes literal：长度可精确计算；
- latin-1 范围 Python `str` literal：按历史 Python2/pwntools EXP 的 byte-compatible 语义计数；
- `tube.recvn(N)`：仅当 `N` 是非负整数字面量时视为 exact N；
- `A + B`：只有 A/B 两侧都 exact 时才合并宽度；
- 普通 `recv(N)` **不**提升为 exact，因为它可能短读；
- 任一子表达式无法证明时保持 UNKNOWN。

对确定的 inline unpack input 新增运行时元信息：

```text
meta_input_width
meta_input_width_evidence
```

并以兼容桥接方式把“总表达式精确宽度”送入现有 `meta_recv_length` leak rule，避免为了本轮修复引起 PackOp schema/baseline 大规模漂移。

没有 challenge name、binary hash、StarCTF 地址或 `puts` 特判。

## 7. Evidence chain

StarCTF 真实表达式现在得到：

```text
RECVN_EXACT(6)
  + LITERAL_WIDTH(2)
  -> CONCAT_WIDTH(8)
  -> u64 input width = 8
  -> no EXP_LEAK_001
  -> no EXP_LEAK_003
```

这条 evidence chain 可复核，并且与“完整 EXP 当前无法 parse”是两条独立事实；二者没有互相覆盖。

## 8. Tests

新增：

`pwncraft/tests/test_inline_unpack_width.py`

覆盖：

1. `u64(io.recvn(6) + b'\x00\x00')` -> exact 8；
2. Python2 风格 `u64(io.recvn(6) + '\x00\x00')` -> exact 8；
3. `recv(6) + padding` -> 仍然 UNKNOWN，不把普通 recv 冒充 recvn；
4. `recvn(5) + b'\x00'` -> exact 6，仍触发 short-read error。

真实材料 regression：

`autocorrect/tests/test_cycle10_starctf2018_note_training_case.py`

验证：

- StarCTF case 位于唯一 `train` split；
- 完整归档 EXP 的第 11 行 parse defect 仍明确可见；
- 从真实文件逐字抽出的 leak RHS 与锁定 truth 一致；
- 该 RHS 得到 exact width 8 与完整 evidence chain；
- 不再产生假 `EXP_LEAK_001/003`。

## 9. Regression

GitHub Actions `Recognizer training gate` run #92，head：

`1ba4e7330ab7d80eb6c6531ae882032609a18276`

结果：SUCCESS。

- project regression：`497 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`37 passed`；
- accepted truth regression：
  - lab13：`MATCH`；
  - note2：`MATCH`；
- gate：`failed=False -> exit 0`。

## 10. What is NOT claimed

本轮不声明：

- StarCTF 2018 note 整题已经 PwnCraft MATCH；
- 原归档 EXP 已被修复；
- 真实 RIP 已观测可控；
- one_gadget 约束已验证；
- 远程 libc leak 已重新执行验证。

FULL CASE 仍停在其真实 upstream `EXP_PARSE` material blocker。

## 11. 下一轮跨比赛计划

Cycle-11 不继续围绕 StarCTF 特判，切换到另一个公开知名比赛题库。

优先候选：DownUnderCTF 官方公开题库 `Challenges_2023_Public` 的 `pwn/roppenheimer`。该题源码与官方 solve 同时公开，适合训练不同于前两轮的真值链：

```text
source bounds relation
-> stack OOB write/copy condition
-> stack pivot intent
-> ROP leak chain
-> libc base provenance
-> second-stage control flow
```

这能把 curriculum 从“普通 ret2libc / leak unpack”扩到 `OOB + stack pivot + ROP + leak`，同时继续保持 Heap / Format / Syscall 等 lane 的后续交错训练。
