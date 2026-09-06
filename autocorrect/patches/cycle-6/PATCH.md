# cycle-6 — Reviewed TargetBehavior 1:N allocator replay

状态：ACCEPTED（2026-09-06）

分支：`main`（本轮经用户明确授权直接修改）

目标阶段：`ALLOCATOR`

TargetBehavior revision：`target-behavior-2026.09-r2`

AllocatorReplay revision：`allocator-replay-2026.09-r1`

## First divergence

Cycle-5 已证明一次 EXP helper 调用可以由 reviewed target behavior 降低为 N 个目标内部动作，但 `GlibcHeapEngine` 仍只回放原 canonical/legacy operation。因此 lab13 当时仍是：

- `create(...)` 在 TargetBehavior 中是两次 malloc，但 replay 只有一次 alloc event；
- `delete(idx)` 在 TargetBehavior 中是两次 free，但 replay 只有一次 free event；
- struct/content 的真实分配顺序、请求大小与对象身份没有进入 allocator 状态。

Cycle-6 只解决这条断层：

`Canonical parent op` → `reviewed TargetBehavior N actions` → `internal allocator child ops` → `GlibcHeapEngine` → `collapse to canonical parent snapshot`

## 关键约束

- CanonicalIR 不拆：一次 EXP helper 调用仍只有一个 canonical parent op。
- 只有 reviewed binding 且确实存在 allocator 1:N（同一 parent 有多个 malloc/free）时才启用 grouped replay。
- reviewed 1:1 case 保留已有 identity replay，避免为了 1:N 修复重写已经接收的单动作语义。
- 不执行 EXP，不进行第二次 source analysis。
- allocator 内部动作顺序严格按 reviewed effects 顺序。
- logical handle 分配不能靠 helper 名或调用次数猜测；需要明确 reviewed `handle_policy`。
- internal free 必须按 role 解析到先前 internal allocation；无法解析直接阻断，不猜 chunk。

## 实现

新增 `autocorrect/allocator_replay_v2.py`：

- `requires_grouped_replay()`：只有真实 1:N allocator binding 才启用新 replay；
- `build_replay_plan()`：把 canonical parent 转为内部 malloc/free child operations；
- internal chunk 使用 parent op + role 的稳定身份，例如 `op_001__management_struct` / `op_001__content`；
- `bind_handle` 明确指定哪个内部 allocation 承担菜单/逻辑 handle；
- `collapse_snapshots()`：内部 N 个 allocator snapshot 聚合回一个 canonical parent snapshot，保留 parent `op_id`，同时聚合 N 个 alloc/free/read/write/bin-transition event；
- `replay_session()`：复用已经完成的一次分析，只替换 provisional identity replay，不重新解析源码。

新增 `autocorrect/pwncraft_adapter_v2.py`：

- 一次 `HeapSession.load` 完成正式 source analysis；
- reviewed 1:N case 进入 grouped allocator replay；
- reviewed 1:1 / 无 1:N case 保持原 replay；
- 最终 run manifest、replay、physical/canvas sidecar 全部来自 grouped replay 后的状态；
- 新增 `allocator_replay_plan.json` 审计 sidecar。

`target_behavior_v2.py` 升到 r2：

- reviewed binding 可携带严格 `handle_policy`；
- malloc action 显式保留 `bind_handle`；
- 当前支持的 handle policy 为 `lowest_free_index`，必须给出正整数 limit。

lab13 binding 根据 `heapcreator.c` 已审查事实加入：

- `heaparray[10]`；
- create 从 0 开始扫描首个空 slot；
- create 的 struct malloc 不绑定 handle，content malloc 绑定 handle；
- delete 按 content → management_struct 顺序 free，随后该 slot 可复用。

## lab13 allocator 结果

现在 allocator replay 的真实内部顺序为：

1. create0：`malloc(0x10)` struct0 → `malloc(0x18)` content0；
2. create1：`malloc(0x10)` struct1 → `malloc(0x10)` content1；
3. edit0 仍通过 logical handle 0 写 content0；
4. delete1：`free(content1)` → `free(struct1)`；
5. 后续 create 在 reviewed `lowest_free_index` 下复用 logical slot 1，并仍按 struct → content 顺序执行两次 malloc。

正式 comparator 的 `ALLOCATOR` 层已从 deferred 移入 lab13 required layers；它现在要求 TargetBehavior malloc/free 数量与 parent replay step 的 allocator events 数量一致，并核对 malloc request。

## 回归与一次失败修正

新增/扩展回归：

- `autocorrect/tests/test_allocator_replay_v2.py`：grouped parent event 聚合、slot 复用、free role 严格解析、unreviewed identity 路径；
- `autocorrect/tests/test_target_behavior_v2.py`：handle policy / bind_handle 严格性。

本轮中间门禁曾暴露一个有效泛化问题：note2 是 reviewed binding，但 allocator 行为是 1:1。首版 grouped planner 对所有 reviewed alloc/free 都做 child-role lowering，使 note2 的单 free 缺少多对象 role 映射而被 BLOCKED。修正后 grouped replay 只在“真实 1:N allocator action”存在时启用，1:1 case 保持原 identity replay。该修正不是 case-id 特判。

## 正式接收门禁

GitHub Actions `Recognizer training gate` run #50，在 `ALLOCATOR` 已为 lab13 required layer 的条件下：

- project regression：`471 passed, 1 skipped, 6 subtests passed`；
- autocorrect regression：`18 passed`；
- accepted truth：
  - `heap-ctf-wiki-hitcontraning-lab13-bae716d5: MATCH`；
  - `heap-ctf-wiki-2016-zctf-note2-a85b75f2: MATCH`；
- gate：`failed=False -> exit 0`。

因此 Cycle-6 接收：TargetBehavior 的 reviewed allocator 1:N 已真实进入 allocator replay，而不是只停留在审计 sidecar。

## 下一层

本轮不借 ALLOCATOR 的 MATCH 宣称物理布局、bins 或 canvas 已闭环。lab13 下一未验收层从 `PHYSICAL_MEMORY` 开始：需要把 internal struct/content 的物理对象身份、相邻关系、overlap 与 stale/alias 视图逐条变成可比较真值，再决定是否继续推进到 BINS。
