# cycle-4 — size-only alloc contract

状态：ACCEPTED（2026-09-06；current-head GitHub gate + accepted truth regression 均通过）

分支：`training/gpt-cycle-4-size-only-alloc-v2`

识别器：`recognizer-2026.09-r6`

## First divergence

本轮处理的是经典单参数分配 helper：

- babyheap：`allocate(size)`，`Size:` prompt 后 `sendline(str(size))`
- stkof：`alloc(size)`，无 `Size:` prompt，但先发送菜单选择 `1`，再 `sendline(str(size))`

旧 `_structural_contract` 能从参数名/提示词得到 size 线索，但 operation 决策链没有 `size-only` 分支，因此 helper 仍保持 `operation=unknown`。历史 divergence report 已记录这一根因。

## 规则

本轮不按题名、case id 或 challenge hash 硬编码。新增的通用证据路径要求：

1. helper 只有一个参数；
2. 该参数真实流入 send/write 族调用；
3. 参数角色必须由以下任一路径证明为 SIZE：
   - 最近的 `Size/Length/Bytes/...` prompt；
   - `sendafter/sendlineafter` 的内联 size prompt；
   - promptless 菜单 wrapper 使用约定的 size 参数名，且在参数发送前已有独立常量/control outbound send；
4. 只有在上述结构形状已经成立后，ALLOC 名称候选才允许负责消歧；
5. 没有参数流、没有 size 角色、没有独立 prompt/control 证据、或不是 ALLOC 候选时保持 UNKNOWN。

特别拒绝：`def allocate(size): sendline(str(size))`。仅靠 helper 名称 + 参数名 + 自身发送不能自举成结构证据。

## 实现

- 新增 `pwncraft/pwncraft/features/heapviz/contracts/promotions.py`
  - 包装现有 resolver，不改动旧 resolver 的已接受路径；
  - 增加 size-only alloc 的后置结构促销；
  - prompt 证据与 promptless control-send 证据分开记录；
  - 显式 analyst/profile/user truth 继续优先；
  - lowering 默认使用促销后的 resolution。
- `pwncraft/pwncraft/features/heapviz/contracts/__init__.py` 的公共入口切到 promotions 层；现有包级调用者无需改 API。
- `RECOGNIZER_REVISION` 在正式接收本行为变化时由 r5 提升到 r6。

## 回归设计

`pwncraft/tests/test_contract_size_only_alloc.py` 共 7 项。

正例：

- `allocate(amount)`：参数名不是 size，但 `Size:` prompt 将其绑定为 SIZE；
- stkof 形状 `alloc(n)`：先发送固定菜单选择，再发送 n，无 size prompt；
- lowering 后 `allocate(0x80)` 必须得到 canonical ALLOC 且 menu request 为 `0x80`。

近似反例：

- bare `allocate(size): sendline(size)`：无独立 prompt/control 证据，不得提升；
- `allocate(token)` + `Token:`：alloc-like 名称不得单独证明；
- `allocate(size)` 但 outbound 是固定字符串：无 parameter flow，不得提升；
- `resize(size)`：size shape 存在但不是 ALLOC 候选，不得提升。

## 验收结果

最终验收在 PR merge ref 上执行，而不是依赖旧的本地 harness：

- PwnCraft project regression：`471 passed, 1 skipped, 6 subtests passed`；
- autocorrect infrastructure regression：`8 passed`；
- artifact-aware accepted truth regression：
  - `heap-ctf-wiki-hitcontraning-lab13-bae716d5: MATCH`
  - `heap-ctf-wiki-2016-zctf-note2-a85b75f2: MATCH`
- gate 总结：`failed=False -> exit 0`。

为关闭旧 truthregress 的 sidecar 完整性盲点，本轮额外增加 `autocorrect/truthregress_ci.py`：每个 accepted case 都进行 fresh authoritative run，把 sidecars 写入 `generated/truthregress/`，在保持 evaluation contract 的 layer applicability 前提下，再对真实 artifact 目录执行完整性门禁。这个修复只修验收路径，不改变识别器语义。

此前一次 CI 暴露并修复了 `pwncraft_adapter.py` 中未定义 `ROOT` 导致正式 run/truthregress 崩溃的问题；当前已使用 `_OUTER / "autocorrect" / "cases"` 解析 behavior bindings。

## 接收结论

满足本轮全部接收条件：

- cycle-4 新增回归通过；
- 当前仓库全量 pytest 无退化；
- babyheap helper 从 UNKNOWN → ALLOC(size)；
- stkof helper 同规则自动生效；
- bare/name-only/token/resize 近似反例保持不提升；
- lab13/note2 已接受真值均保持 MATCH；
- recognizer revision 已递增至 r6；
- 规则已登记为 `R-SIZE-ONLY-ALLOC-STRUCTURAL-PROMOTION`。

下一 first-divergence 不在本轮顺手修。能力队列推进到 `TARGET_BEHAVIOR 1:N`（lab13 create/delete 的目标内部多 malloc/free 行为）。
