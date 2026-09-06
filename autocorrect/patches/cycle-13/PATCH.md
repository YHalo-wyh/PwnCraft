# cycle-13 — SekaiCTF 2026 echo-chamber / Source+EXP Modular Integer Composition

状态：**ACCEPTED（cross-material integer evidence sublayer）** · 2026-09-06

Domain：`integer -> memory_write -> heap`

Train case：`integer-sekaictf-2026-echo-chamber-99fc2e72`

来源：Project Sekai 官方 `sekaictf-2026` challenge archive，`pwn/echo-chamber`。

## 1. Why this stayed on the same 2026 challenge

本轮继续 latest-first，但没有为了“换新题”降低材料标准。比 SekaiCTF 更晚的 2026 题目已经进入候选池；若只有社区 writeup / exploit、缺官方 binary/source/solution，则只能作为 validation 候选，不能驱动 patch。

`echo-chamber` 仍然拥有完整官方 source + binary + libc/ld + official solution，因此继续沿上一轮的 first unclosed layer 推进：

```text
source signedness relation
+ official EXP literal input
-> exact modular value relation
```

## 2. Truth revision discipline

Cycle-12 的 `expected_truth.json` 保留不动。

新增：

`expected_truth_cycle13.json`

truth revision 从 v1 增量到 v2，明确记录 `supersedes`，不覆盖旧 truth。

## 3. First divergence

Cycle-12 已经能够证明：

```text
strtoll(...)
-> size_t body_len
-> malloc(body_len + 1)
-> readn(..., body_len)
```

但仍有两个缺口：

1. source fact 与官方 solution 中的 `Content-Length: -1` 还没有可复核的组合层；
2. 官方 handler 是 `void *handle_connection(...)`，旧低层 C header recognizer 对 pointer-return function 的 scope 标注可能退化成 `<global>`，导致 provenance 不够精确。

因此本轮不继续猜 allocator 行为，而先补：

```text
source field binding
-> EXP literal field
-> exact signed value
-> unsigned conversion
-> allocation/copy modular relation
```

## 4. Generic patch

新增：

`pwncraft/pwncraft/features/audit/integer_flow.py`

它位于低层 `c_source_ir` 之上，只组合已经存在的 source facts 与 EXP AST literal evidence。

支持的窄形状：

- source 中存在 `find_header(..., "Field")`；
- 已识别的 signed parser 消费该对象的 `->val`；
- Python EXP 中存在字面量 `Field: signed-decimal`；
- 不执行 EXP；
- 不进行网络请求；
- 不把 source+EXP evidence 冒充 runtime observation。

新增 composed fact kinds：

```text
EXP_INPUT_REACHES_SIGNED_PARSER
UNSIGNED_CONVERSION_EXACT_MAX
ALLOCATION_ARGUMENT_WRAP_TO_ZERO
COPY_BOUND_REMAINS_UNSIGNED_MAX
```

其中只有 literal `-1` 才升级为 exact unsigned max：

```text
(-1) mod 2^N = 2^N - 1
```

如果 allocation expression 是 `tracked_unsigned + 1`：

```text
(2^N - 1 + 1) mod 2^N = 0
```

copy bound 仍保持：

```text
2^N - 1
```

这里的 N 由后续 target ABI/type facts 提供；上述恒等式对任意 unsigned width 成立，所以本轮不需要偷猜 32/64 位。

## 5. Provenance repair

新的 composition layer 自己做保守的 C function-span 识别，支持：

```c
void *handle_connection(...)
static char *lookup(...)
Header *find_header(...)
```

同时显式排除 `if/for/while/switch`，只用于把低层 `<global>` fact 按同一 source line 重新绑定到真实函数 scope。

这不会修改 semantic fact，只修复 provenance label。

## 6. Negative controls

新增 tests 确保：

- `Content-Length: 8` 只能证明 input reaches parser，不产生 wrap；
- EXP 只有 `X-Length: -1` 时不得误绑到 `Content-Length`；
- source 没有 `find_header` channel binding 时不得从同名字符串猜输入通道；
- EXP 语法错误时 composition BLOCKED，但 source facts 仍可保留；
- source+EXP 结果不得宣称 malloc(0) 的实现行为、完整 read 成功或具体 overwrite extent。

## 7. Real challenge truth

官方 source：

```c
Header *content_length = find_header(headers, "Content-Length");
size_t body_len = strtoll(content_length->val, &end, 10);
body = malloc(body_len + 1);
size_t nbytes = readn(self->fd, body, body_len);
```

官方 solution literal：

```text
Content-Length: -1
```

Cycle-13 因而能够发布：

```text
EXP_INPUT_REACHES_SIGNED_PARSER
  field = Content-Length
  input = -1

UNSIGNED_CONVERSION_EXACT_MAX
  body_len = 2^N - 1

ALLOCATION_ARGUMENT_WRAP_TO_ZERO
  body_len + 1 = 0 mod 2^N

COPY_BOUND_REMAINS_UNSIGNED_MAX
  readn bound = 2^N - 1
```

仍然全部属于 source/EXP-derived evidence，不是 runtime fact。

## 8. Tests / CI

新增 project regression：

`pwncraft/tests/test_integer_flow_evidence.py`

新增 training regression：

`autocorrect/tests/test_cycle13_sekaictf2026_integer_composition.py`

GitHub Actions `Recognizer training gate` run `34040788397`：**SUCCESS**。

- project regression：`513 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`51 passed`；
- accepted truth regression：
  - lab13：`MATCH`；
  - note2：`MATCH`；
- gate：`failed=False -> exit 0`。

## 9. What is NOT claimed

本轮不声明：

- `echo-chamber` 整题已 MATCH；
- `malloc(0)` 的返回值或 glibc 行为已由本层证明；
- `readn` 实际完成了 `SIZE_MAX` 字节读取；
- runtime overwrite extent 已观测；
- multi-arena / large-bin / TLS cancellation / exit handler 链已建模；
- 任意负整数都等于 unsigned max；只有 `-1` 有该 exact identity；
- 任意出现 `Content-Length` 的 EXP 都与 source parser 存在连接。

## 10. Next first unvalidated layer

下一轮优先切换比赛/漏洞域，避免连续对单题过拟合。

候选顺序：

1. 2026 年 8–9 月、官方 source/binary/solution 齐全的 Stack / Format String / Control Flow 题；
2. 若最新比赛只有社区材料，则先登记 validation，不用于 patch selection；
3. 如果短期没有可信的新官方题，再回 `echo-chamber`，进入 target ABI width + allocator-context（tcache disabled / multi-arena）层；
4. Heap 的 lab13 PHYSICAL_MEMORY/BINS 继续保留并行 lane，但不垄断训练。
