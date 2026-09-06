# PwnCraft Heap Recognition Trainer — 长期训练协议（锁定版）

状态: LOCKED 2026-09-03; v1.1 修订 2026-09-03; **v1.2 修订 2026-09-03 (cycle-1 执行前, 协议所有者批准)**。
来源: 用户提供的主提示词（行为约束的权威文本，本文件为其工程化落盘）。

## 目标

用真实公开 Heap Pwn 题作 curriculum，通过
「独立分析 → PwnCraft 回放 → 第一偏差定位 → 通用规则修复 → 回归验证」循环，
持续提升 PwnCraft 对 Heap EXP 的静态识别能力
（alloc/free/edit/show/copy、helper wrapper、参数角色 index/size/data、
wrapper-of-wrapper、loop、chunk handle、allocator request、overwrite/overlap、
bin 状态、每步 PhysicalMemory/Snapshot），最终生成与真实 glibc 行为一致的堆画布。

## 核心等式

```
One Cycle = One First Divergence = One Minimal Generic Patch = One Regression Result
```

每轮只修第一处偏差；即使后面还有十个错误也禁止顺手修改。
修完重跑当前 Case、重新生成 PwnCraft 输出、重新寻找新的 first divergence。

## 两阶段隔离

- 阶段 A（Clean-room Ground Truth Analyst）: 只读题目材料（binary/source/libc/ld/exp/官方
  writeup），**禁止**读取任何 PwnCraft 输出（recognition/contracts/IR/snapshot/memory/
  canvas/diagnostics/旧 divergence report）。产出 `expected_truth.json` 并落盘锁定；
  锁定后本轮不得为迎合 PwnCraft 而修改。证据不足写 UNKNOWN，禁止猜。
- 阶段 B（Baseline + Review + Repair）: expected_truth 落盘后才允许运行 PwnCraft，
  保存原始输出至 `generated/`（识别、契约、IR、operations、snapshots、bins、物理内存、
  paint spans）。不得先人工修正。

## 分层取证（禁止以 EXP 命名代替 binary truth）

- A. EXP/wrapper 证据: `recvuntil("Size:") + sendline(str(size))` 证明参数与菜单输入的
  数据流关系（中等强度），不直接证明 malloc request == size。
- B. binary/source 证据: `ptr[idx] = malloc(size)` 强证明 allocator_request = size；
  `malloc(size + 0x10)` 则期望值为 size + 0x10。
- C. libc/allocator 证据: 按 glibc profile 判定 tcache/safe-linking/fastbin/unsorted/
  consolidation/bin transitions。

## 比较层序（发现第一处不一致立即停止）

```
1 HelperContract        2 Static Recognition    3 Canonical IR
4 Argument/value binding 5 Allocator event     6 chunk logical mapping
7 PhysicalMemory        8 bins                  9 Snapshot
10 Canvas renderer
```

## PROMPT_SYNC ≠ OUTPUT_DATA_FLOW

`recvuntil("Index:")` 等是 PROMPT_SYNC，禁止当 SHOW 证据。
只有 recv 结果的数据流（赋值/返回/进入后续计算）才构成 OUTPUT_DATA_FLOW；
`index + OUTPUT_DATA_FLOW` 才是较强 SHOW 证据。

## 修复纪律

- 修改前建立 checkpoint（本仓库非 git，用文件级备份 + diff 存档）。
- 本轮只允许修改解决该 first divergence 所需的最小代码集合；通用、最小、可解释、
  有测试、不改无关行为；新增至少一个 unit/regression test，测试用合成用例，
  不得使用当前 challenge 名字。
- 禁止: `if challenge_name == ...`、binary hash 特判、地址特判、函数名硬编码、
  扩充 `_FUNC_ALIASES`/`_ROLE_ALIASES` 来收录真实题目函数名。
  函数名只能作弱证据之一。
- 重跑禁止复用修改前的中间结果。

## 接受条件（全满足才 ACCEPT，否则 REVERT）

1. 当前 first divergence 已修复
2. 当前 Case 未出现更早的新 divergence
3. unit tests PASS
4. truth regression PASS（已 ACCEPTED 的 Case 继续满足锁定 truth）
5. stability regression PASS（未受影响的历史题无漂移；受影响者的漂移必须可解释，
   baseline 仅随 ACCEPT 同步显式刷新）

禁止: 为通过回归修改 expected truth；regression 失败后偷偷刷新 baseline；
把 UNKNOWN 强转成猜测值；直接改 Canvas 数据让画布好看；用截图当 allocator truth；
writeup 覆盖 binary evidence；未经隔离 sandbox 执行来源不可信 binary。

## 泛化跟踪

Case A 教会的规则须在 Case B/C 的不同函数名/相同数据流结构上免校正生效
（GENERALIZATION_SUCCESS），否则不得记为泛化成功。

## Corpus 分层

Recognizer Corpus（helper/wrapper/roles/loop/alias/callsite/IR）与
Allocator Gold Corpus（glibc 行为/tcache/fastbin/unsorted/smallbin/largebin/
safe-linking/consolidation/overlap）分开评测，不混用指标。

## 节奏

先用现有 GOLD Case 连续跑通 3-5 道题确认闭环稳定，再谈 batch-2 扩充。

## 处理队列（本工作区定义）

| 序 | case | 状态 |
|---|---|---|
| 0 | babyheap + 旧 patch 轮 | **cycle-0-bootstrap-invalidated**（归档于 `patches/cycle-0-bootstrap-invalidated/`，不作 held-out） |
| 1 | heap-ctf-wiki-hitcontraning-lab13-bae716d5 | **cycle-1（本轮）**: show SEMANTIC_MATCH/EVIDENCE_DIVERGED |
| 2 | heap-ctf-wiki-2014-hitcon-stkof-13e0c84f | 待处理 |
| 3 | heap-ctf-wiki-2015-hacklu-bookstore-8bd55c59 | 待处理 |
| 4 | heap-ctf-wiki-2015-9447ctf-search-engine-3a28f615 | 待处理 |
| 5 | heap-ctf-wiki-2016-zctf-note2-a85b75f2 | 待处理 |
| 6 | heap-ctf-wiki-2017-insomni-hack-wheelofrobots-ebbbaf52 | 待处理 |
| 7 | heap-ctf-wiki-zerostorage-c06ff06c | 待处理 |

## 每轮汇报格式

CASE / CYCLE / FIRST DIVERGENCE / ROOT CAUSE / PATCH / WHY GENERIC /
CURRENT CASE RESULT / REGRESSION / GENERALIZATION IMPACT / NEXT ACTION

---

# v1.1 修订（2026-09-03, 协议所有者批准）

## A. First Divergence 定义升级（推翻 unmasking 例外提案）

不批准「unmasking 例外 = mismatch 总数不增即可接受」。比较必须同时覆盖
**语义结果**与**产生该结果的 evidence/provenance**：

- `semantic=SHOW` 但依据是错误的 `index+recvuntil(prompt)` 推理
  → 记为 **SEMANTIC_MATCH / EVIDENCE_DIVERGED**，这是合法的 first divergence，
  不视为完全 MATCH。
- 「答案碰巧正确但理由错误」必须能成为 divergence。

## B. HelperContract 比较字段（至少）

comparator 对每个 helper 至少比较六元组：

1. semantic
2. argument_roles
3. confidence
4. evidence_type
5. evidence
6. provenance

## C. PROMPT_SYNC 规则必须 evidence-based

禁止实现为 `recvuntil(常量字面量) + 返回值未用 ⇒ 必然 PROMPT_SYNC` 的硬编码判断。
正确形态：

- 未使用的 `recvuntil(常量)` → **PROMPT_SYNC candidate**（仅候选）
- 紧邻的 `send/sendline(parameter)` → **strong prompt-sync evidence**（升级为强证据）
- prompt 文本形状（Size/Index/Content 等）→ **弱证据**

## D. 1:N allocator events

一个 Helper/Canonical call 可以产生多个 allocator events，例如 lab13：

- `create(size)` = `malloc(0x10)`（management struct）+ `malloc(size)`（content）
- `delete(index)` = `free(content)` + `free(struct)`

comparator 不得默认 one helper call = one malloc/free。
**术语禁令**：此类模式必须称 "two free calls / free(content)+free(struct)"，
禁止称为 double_free——它不是 double-free 漏洞。

## E. Baseline 版本化（禁止破坏性覆盖）

- 每个基线记录 `patch_id` / `label`(pre-patch|post-patch) / `intentional_delta` /
  `digest` / `fingerprint` / `note`，完整版本历史不可覆盖。
- **accepted_truth 一旦锁定，不得因 patch 自动刷新。**
- 回归判定针对全部历史版本报告对齐状态，而非只对最新版。

## F. cycle-2 前置约束

- `show` 修复禁止简单把 fallback `candidate_operation` 提升为真实 operation；
  candidate 只能作候选证据。优先实现调用点级 OUTPUT_DATA_FLOW：
  recv 返回值被赋值/返回/打印/进入后续计算 → SHOW strong evidence；
  recvuntil prompt 且返回值丢弃 → 不构成 SHOW strong evidence。

---

# v1.2 修订（2026-09-03, 协议所有者批准, cycle-1 执行前）

## G. 历史编号不可抹除

旧轮次不删除、不覆盖，仅标记失效。`cycle-0-bootstrap-invalidated` 归档于
`patches/cycle-0-bootstrap-invalidated/`（旧 divergence report、旧 comparator 版本、
旧 patch、作废原因）。v1.1/v1.2 语义下的第一轮正式训练编号为 **cycle-1**。

## H. SHOW 与 FREE/DELETE 的证据定义（修正 v1.1 §C 的表述）

- **SHOW**: OUTPUT_DATA_FLOW 是强结构证据 —— recv/recvn/recvline 的结果被
  赋值、返回、打印或进入后续计算才可成为 SHOW 强证据。
  PROMPT_SYNC（recvuntil(prompt) + 后续 send 参数等模式）只能证明交互同步/
  参数绑定，不能作为 SHOW 输出证据。
- **FREE/DELETE**: **不要求 OUTPUT_DATA_FLOW**。必须通过独立正证据推断，例如：
  source/binary 对应菜单分支进入 free()、pointer table[index] 流入 free、
  index 参数对应被释放对象、wrapper/branch/callsite data-flow、slot 清理等
  后续行为。
- **PROMPT_SYNC 被排除出 SHOW 证据后，不得自动得出 DELETE**；
  DELETE 必须有自己的正证据。

## I. TARGET_BEHAVIOR 层

管线正式调整为：

```
EXP → HelperContract → Canonical IR → TargetBehavior → AllocatorEvents
    → PhysicalMemory → Bins → Snapshot → Canvas
```

- `target_behavior` 属于 target binary/source semantics（如 lab13 的
  `create(size) → malloc(0x10) + malloc(size)`、
  `delete(index) → free(content) + free(struct)`）。
- expected_truth 中 `target_behavior` 与 `allocator_events` **分开保存**；
  allocator comparator 验证这些动作是否产生了正确 allocator events。
- **禁止要求 HelperContract 单独凭 EXP 推出隐藏的内部 malloc/free**。


---

# v1.3 修订（2026-09-05, 协议所有者指令: 视觉审查策略调整）

## J. CANVAS_SEMANTIC_MODEL 中间真值层

- renderer 绘制前，每个 heap state change step 导出 `canvas_semantic_model.json`
  （实现: `pwnbao/features/heapviz/canvas_model.py`，来源 = bridge step 载荷 +
  PhysicalGrid 行模型 + HeapSceneLayout 常量；禁止从截图 OCR 反推）。
- 比较层序追加: ... PHYSICAL_MEMORY → SNAPSHOT → **CANVAS_SEMANTIC_MODEL**。
- 14 条 invariant 由 `check_canvas_invariants` 执行；判据语义化:
  inv7 仅在无改尺寸证据(original==extent)的 top 覆盖时报警（伪造 size 的
  合法重叠是画布必须呈现的语义真值）；inv9 仅对真 bin 家族位置要求成员一致性
  （'top' 等溯源伪位置除外）。

## K. 视觉审查降级策略

- 默认只读结构化数据（JSON evidence 优先）。
- Screenshot / Computer Observer 仅限: (A) 结构层全 MATCH 但怀疑真实显示错误;
  (B) text clipping/DPI/CSS/font/arrow overlap/viewport/zoom/hit-testing/hover/
  selection 等纯呈现问题; (C) 随机视觉 regression 抽检。
- 截图不得作为 allocator/physical truth。

## L. Token Budget 原则

JSON structured evidence > small relevant source slice > full source file > screenshot。
每次只提供解决当前 first divergence 所需的最小上下文；Code review 按需读取
（仅当偏差定位到 CANVAS_SEMANTIC_MODEL 才读 renderer/layout 相关函数）。
