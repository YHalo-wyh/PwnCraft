# cycle-5 — TargetBehavior 1:N formal plumbing

状态：IN PROGRESS

分支：`training/gpt-cycle-5-target-behavior-1n`

目标阶段：`TARGET_BEHAVIOR`

TargetBehavior revision：`target-behavior-2026.09-r1`

## First divergence

Cycle-4 之后，lab13 的解析、HelperContract、CanonicalIR 与参数绑定已经作为 accepted truth 固定。下一最早结构缺口是：一次 EXP helper 调用在目标程序内部可能对应多个 allocator action。

lab13 的锁定真值明确证明：

- `create(size, content)` → `malloc(0x10)` 管理结构 + `malloc(size)` 内容块；
- `delete(idx)` → `free(content)` + `free(struct)`；
- 这是 two free calls，不是同一块的 double-free。

仓库其实已经存在 `BehaviorEffectExpander`、`BinaryIR.build_behavior_profile()` 和 isolated 1:N 测试；缺口不是“完全没有 1:N 实现”，而是正式 `run_case/truthregress` 链没有一个可靠的 CanonicalIR→TargetBehavior 降低阶段。

同时发现旧 `behavior_bindings.json` 仍使用 legacy `helper` 字段，而严格 `ChallengeCallBehavior` 需要 `function`；旧 adapter 直接把 legacy JSON 送入严格 parser，并用 `except Exception: pass` 静默丢弃失败。因此行为绑定从未成为正式验收证据。lab13 绑定本身还残留 `free/dump` 与三参数 `edit` 等旧 helper 形状，与当前 corpus EXP 的 `delete/show/edit(idx, content)` 不一致。

## 本轮边界

Cycle-5 只修 TargetBehavior stage，不提前修下游 allocator replay：

`CanonicalIR (1 helper call)`
→ `reviewed behavior binding`
→ `TargetBehavior (N internal actions)`

明确不做：

- 不把一个 EXP helper 强行改成多个 CanonicalIR 操作；锁定真值仍是一调用一 canonical op；
- 不让 GlibcHeapEngine 在本轮直接消费 1:N target action stream；
- 不提前宣称 ALLOCATOR/BINS/PHYSICAL_MEMORY 正确；这些层继续 defer；
- 不按 lab13/case id/题名硬编码规则；
- 不执行 EXP 源码，不做第二次 source analysis。

## 实现

新增 `autocorrect/target_behavior_v2.py`：

- 严格读取 reviewed `behavior_bindings.json`；
- legacy `helper` 仅做 schema normalization 到 `function`，其余错误直接抛出，不静默吞掉；
- 消费 fresh authoritative run 已生成的 `analyzer.canonical_ops[].source_call`；
- 使用 Python AST 只解析调用表达式和实参文本，不执行源码；
- 绑定参数后将 effects 降低为 `malloc/free/write/print/copy` target actions；
- 一个 canonical op 可产生 N 个 target actions；
- 没有 reviewed binding 的调用保留旧 identity fallback，并显式 `internals_not_modeled=true`；
- formal gate 中更新 `target_behavior.json` 与 `pwncraft_output.json`，保证内存比较和 sidecar 一致。

lab13 reviewed binding 同步校正为当前 corpus/source truth：

- `create(size, content)`：2 malloc；
- `edit(idx, content)`：1 write；
- `show(idx)`：1 print；
- `delete(idx)`：2 free。

## 验收契约

lab13 `evaluation_contract.json` 已将 `TARGET_BEHAVIOR` 从 defer 移入 required layers。

`ALLOCATOR/BINS/PHYSICAL_MEMORY/SNAPSHOT/CANVAS/RENDERER` 仍保持 defer，因为当前 GlibcHeapEngine 尚未消费 TargetBehavior action stream。本轮只有 TARGET_BEHAVIOR MATCH 才能接收。

## 回归

新增 `autocorrect/tests/test_target_behavior_v2.py`：

1. one canonical create → two malloc actions；
2. delete → two free actions，并保持 role 区分；
3. 未绑定 helper 保持 identity fallback；
4. legacy helper key 可规范化，但 malformed binding 必须失败；
5. keyword 参数只做 AST 绑定，不执行源码。

## 接收条件

- 新增 TargetBehavior 单测全部通过；
- PwnCraft 全量测试不退化；
- autocorrect 全量测试不退化；
- lab13 accepted truth 在新 required TARGET_BEHAVIOR 下仍为 MATCH；
- note2 等既有 accepted truth 不受影响；
- 1:N 结论来自 reviewed source/binary binding，不来自名称猜测；
- 下游 allocator 层保持诚实 defer。
