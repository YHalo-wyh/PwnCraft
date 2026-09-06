# cycle-12 — SekaiCTF 2026 echo-chamber / Signedness-to-Length Truth

状态：**ACCEPTED（source integer sublayer）** · 2026-09-06

Domain：`integer -> memory_write -> heap`

Train case：`integer-sekaictf-2026-echo-chamber-99fc2e72`

来源：Project Sekai 官方 `sekaictf-2026` challenge archive，`pwn/echo-chamber`。

## 1. Latest-first 选题

本轮继续执行 `latest-first + evidence-gated`：优先 2026 新题，但来源可信度优先于单纯追新。

ASIS CTF Quals 2026 `arena-snapshots` 的当前材料来自 participant/community archive，因此已从 `train` 调整到 `validation`；它可以检验通用 socket-wrapper 抽取，但不能作为 patch-selection feedback。

正式训练改用 SekaiCTF 2026 官方仓库的 `echo-chamber`：官方同时公开 challenge source、binary、libc/ld 与 solution，材料链足够完整。

## 2. Clean-room source truth

官方 `chal.c` 的 POST 路径存在如下确定性关系：

```c
size_t body_len = strtoll(content_length->val, &end, 10);
body = malloc(body_len + 1);
size_t nbytes = readn(self->fd, body, body_len);
```

其中：

- `strtoll` 返回 signed `long long`；
- 结果直接进入 unsigned `size_t body_len`；
- 同一个 `body_len` 同时参与 allocation expression 与 `readn` length bound。

该层只证明 source-level signedness/dataflow，不单凭函数名宣称漏洞成立。

官方 solution 另外给出明确输入证据：

```text
Content-Length: -1
```

因此可以把“负输入存在”与 source conversion relation 组合，但仍不冒充本轮 GDB/runtime observation。

## 3. First divergence

PwnCraft 原有 `c_source_ir.py` 可以做保守的 C callsite/value extraction，但没有把以下链条作为一等事实：

```text
signed parser result
-> unsigned storage
-> allocation use
-> byte-copy/read bound use
```

这导致 `integer` domain 虽已存在于项目 capability surface，却缺少可复核的 source evidence chain。

## 4. Generic patch

扩展 `pwncraft/pwncraft/core/c_source_ir.py`，新增 `CIntegerFlowFact` 与 `extract_c_integer_flows()`。

当前规则刻意保持窄范围：

- 只接受 `strtol/strtoll` 这类返回 signed integer 的明确 parser；
- 只在其结果直接赋给 `size_t/uint*_t/unsigned ...` 时产生 `SIGNED_PARSE_TO_UNSIGNED`；
- 只追踪同一函数、同一变量；
- allocation consumer 只记录 `malloc/calloc/realloc` 参数事实；
- copy-bound consumer 只在变量实际位于已知 length/count 参数位时记录；
- parser 名字出现但没有 signed->unsigned flow 时不报；
- 同名变量跨函数不串联；
- 不输出 `vulnerable=true`，只输出 evidence facts。

新增事实：

```text
SIGNED_PARSE_TO_UNSIGNED
UNSIGNED_LENGTH_ALLOCATION_USE
UNSIGNED_LENGTH_COPY_BOUND_USE
```

## 5. Split discipline correction

本轮同时修正前一阶段的材料分级：

```text
ASIS 2026 arena-snapshots
community archive -> validation

SekaiCTF 2026 echo-chamber
official archive -> train
```

因此社区题仍能验证泛化，但正式 patch acceptance 以官方 source-rich case 为基准。

## 6. Tests

新增 core regression：

`pwncraft/tests/test_c_integer_flow.py`

覆盖：

1. signed parser -> size_t -> malloc -> readn 完整链；
2. 只有 `strtoll` 名字但 destination 是 signed 时不得产生 flow；
3. tracked variable 位于错误参数位置时不得产生 copy-bound；
4. 跨函数同名变量不得串联。

新增真实题 regression：

`autocorrect/tests/test_cycle12_sekaictf2026_echo_chamber_training_case.py`

验证：

- case 已登记唯一 `train` split；
- truth 锁定到官方 source/binary/solution blob；
- 官方 source-derived excerpt 得到三段完整 evidence chain；
- 官方 `Content-Length: -1` 只标为 `EXP_SUPPORTED`，不升级成 runtime observation。

ASIS regression 同步修改为 validation-only。

## 7. CI

GitHub Actions `Recognizer training gate` run `34040155185`，head：

`340a435ae24ef4501799c70798985eafdaeb45d6`

结果：**SUCCESS**。

- project regression：`508 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`47 passed`；
- accepted truth regression：
  - lab13：`MATCH`；
  - note2：`MATCH`；
- gate：`failed=False -> exit 0`。

## 8. What is NOT claimed

本轮不声明：

- `echo-chamber` 整题已经 PwnCraft MATCH；
- runtime heap overwrite 范围已经观测；
- 后续 arena/large-bin/TLS/cancellation 利用链已经完整建模；
- 任意 `strtoll` 使用都是漏洞；
- ASIS community archive 是正式训练反馈源。

当前 ACCEPTED 仅针对 `integer/source-flow` 子层。

## 9. 下一步

继续优先 2026 官方/高可信材料，优先扩展：

1. `echo-chamber` 的 allocation-size wrap 与 copy-bound mismatch 精确值域；
2. 官方 solution 中多 arena / tcache disabled 的 allocator context；
3. 再切换另一场 2026 新比赛，避免对 SekaiCTF 单题过拟合；
4. validation lane 保留 ASIS `arena-snapshots`，检验 stdlib socket wrapper 与 object-lifecycle 泛化。
