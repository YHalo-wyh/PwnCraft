# cycle-4 — size-only alloc contract

状态：IN_PROGRESS（实现与定向回归已落分支；尚未登记 ACCEPTED）

分支：`training/gpt-cycle-4-size-only-alloc`

## First divergence

当前能力队列中最早的未闭合项之一是经典单参数分配 helper：

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

这保持了现有原则：name 只用于 recall/disambiguation，不能单独证明语义。

## 实现

- 新增 `pwn宝/pwnbao/features/heapviz/contracts/promotions.py`
  - 包装现有 resolver，不改动旧 resolver 的已接受路径；
  - 增加 size-only alloc 的后置结构促销；
  - prompt 证据与 promptless control-send 证据分开记录；
  - 显式 analyst/profile/user truth 继续优先；
  - lowering 默认使用促销后的 resolution。
- `contracts/__init__.py` 的公共入口切到 promotions 层；现有包级调用者无需改 API。

## 回归设计

`pwn宝/tests/test_contract_size_only_alloc.py` 当前 7 项：

正例：

- `allocate(amount)`：参数名不是 size，但 `Size:` prompt 将其绑定为 SIZE；
- stkof 形状 `alloc(n)`：先发送固定菜单选择，再发送 n，无 size prompt；
- lowering 后 `allocate(0x80)` 必须得到 canonical ALLOC 且 menu request 为 `0x80`。

近似反例：

- bare `allocate(size): sendline(size)`：无独立 prompt/control 证据，不得提升；
- `allocate(token)` + `Token:`：alloc-like 名称不得单独证明；
- `allocate(size)` 但 outbound 是固定字符串：无 parameter flow，不得提升；
- `resize(size)`：size shape 存在但不是 ALLOC 候选，不得提升。

## 已执行的定向验证

在当前会话的隔离 harness 中，使用 2026-09-05 review bundle 的 resolver/model/source_compat 基线，并叠加本轮 promotion：

- cycle-4 size-only 回归：7 项通过；
- cycle-1 `PROMPT_SYNC != OUTPUT_DATA_FLOW` 既有回归：7 项通过；
- 合计：`14 passed`；
- babyheap 真实 helper 形状：`allocate -> alloc`, role=`size`, evidence=`prompt-bound`；
- stkof 真实 helper 形状：`alloc -> alloc`, role=`size`, evidence=`control-send + parameter-bound`。

注意：这是定向兼容验证，不等价于当前 GitHub HEAD 的全量 pytest/truthregress。当前 PR 没有 GitHub Actions workflow run，因此不得据此登记 ACCEPTED。

## 验收纪律

在以下条件全部满足前，不写入 `accepted_rules`：

- cycle-4 新增回归全部通过；
- 当前仓库全量 pytest 无退化；
- babyheap helper 从 UNKNOWN → ALLOC(size)；
- stkof helper 同规则自动生效；
- lab13/note2 已接受断言保持通过；
- 识别器 revision 在正式接收本行为变化时递增；
- 若新的 first divergence 推进到 FREE/DELETE、TARGET_BEHAVIOR 或 allocator 层，只记录为下一轮，不在本轮顺手修。
