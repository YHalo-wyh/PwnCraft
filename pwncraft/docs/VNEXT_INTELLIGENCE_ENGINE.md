# PwnCraft Intelligence Engine — VNext 架构蓝图

状态: 2026-09-05 由协议所有者定调（取代此前 Phase C/D 的 exp 优先路线）；
同日增补 **Offline-First / Deterministic-First 两条硬约束**（见下）。

## 硬约束（所有层级必须遵守）

```text
Offline-First Principle
PwnCraft core MUST NOT depend on:
- Internet access / Cloud APIs / Remote LLM services / External inference endpoints
All core analysis results MUST be reproducible locally.
```

```text
Deterministic-First Principle
If a conclusion can be derived from AST / IR / CFG / data-flow /
target behavior, it MUST NOT rely on probabilistic inference.
```

含义：核心 = 本地静态分析 + 本地状态推演 + 本地规则审计 + 本地交互式修复。
比赛现场价值排序：快/稳/无网络/不吃 token/结果可复现/可解释/可测试/可复盘。
本地大模型永不进入核心架构；未来若需要只作为 `optional_local_assistant/`
插件（有模型 = 多自然语言解释；无模型 = 100% 功能正常）。
三方分工（离线版）：**确定性工具负责理解/验证/解释来源；用户负责修正/创造/
利用思路；本地可选助手（若未来引入）只做自然语言转述。** 自动 EXP 哪怕只能打
40% 的题，程序理解、IDA 联动、Heap Canvas、漏洞证据链仍对每道题有效。

## 四层定义

```
Layer 1  Binary Intelligence    IDA / ELF / CFG / DataFlow     → BinaryIR + Evidence
Layer 2  Vulnerability Intelligence  漏洞 / 原语 / 生命周期    → Hypothesis / Knowledge Graph
Layer 3  Exploit Intelligence   策略图 / 自动验证 / EXP        → Primitive Graph / Strategy Planner
Layer 4  Human Intelligence     Canvas / 编辑 / 推演 / 教学    → 现有 Heap Canvas 的升级方向
```

现有资产映射：
- Layer 1: `core/ida_bridge.py`（MCP client，已完成）+ `core/binary_ir.py`（VNext.1，已完成）
  + `core/static_facts.py`（objdump 级事实，已有）
- Layer 2: `features/heapviz/`（堆语义/contract/IR）+ `autocorrect/`（evidence ownership /
  expected_truth 分层取证 = Evidence 思想的工程化）+ VNext.3 待建
- Layer 3: `features/heapviz/codegen.py`（pwntools 行生成）+ VNext.5/6 待建
- Layer 4: `features/heapviz/grid|presentation/` + `pwncraft-electron/`（Canvas 已是
  PhysicalMemory 的 UI 投影；升级方向 = Knowledge Graph 的 UI 投影）

## VNext 路线

### VNext.1 — IDA Bridge + BinaryIR（本轮已落地核心）
- `core/ida_bridge.py`: 纯 stdlib MCP client；stdio/HTTP 双传输 + **legacy SSE**
  （v1.7.x 实测）；`analyze_binary` 一键提取（metadata/functions/alloc_xrefs）；
  `detect_environment` doctor。
- 实测纪律（Windows + idalib，全部踩坑后固化）：
  1. 子进程 stdout/stderr **禁止**留 unread PIPE（uvicorn 日志写满管道缓冲 →
     服务器阻塞假死）；重定向到日志文件。
  2. cwd 必须 ASCII（TEMP 可）；非 ASCII cwd 实测挂起。
  3. idalib 会在 input 旁留解包库（id0/id1/...）；**强杀进程必损坏解包库**，
     之后一切分析挂死/FATAL。防线 = 每次分析前删旧解包库 + 失败必杀子进程。
  4. v1.7 API: `list_functions(offset,count)` 分页、`get_xrefs_to(addr)`
     返回**连续多个 JSON 对象**的 text（一对象=一调用点）、无 imports 工具
     （用 xrefs_to(PLT) 替代）、`decompile_function/disassemble_function`
     依赖 PySide6（headless 当前缺 GUI Qt 时自动降级，见 degrade_notes）。
- `core/binary_ir.py`: BinaryIR/Evidence/BehaviorLabel 三 schema +
  `build_binary_ir(facts)` 确定性提取。lab13 实证：malloc PLT 0x400700 的
  2 条 code xref → create_heap（= malloc(0x10)+malloc(size) 1:N 铁证）；
  free 0x400690 2 条 → delete_heap（two free calls, 非 double_free）。
- 待补: TargetContext.ida_facts 的 rpc 写入（字段已加）、前端按钮。

### VNext.2 — Semantic Function Recognition（下一优先）
- 输入空间：CFG + API 调用 + 参数数据流 + 字符串 + 全局读写 + 内存行为。
- 输出空间（`binary_ir.BEHAVIOR_LABELS`，已定义）：
  ALLOCATE_OBJECT / FREE_OBJECT / READ_OBJECT / WRITE_OBJECT /
  CLEAR_POINTER / KEEP_POINTER / CHECK_INDEX / NO_INDEX_CHECK /
  CHECK_SIZE / TRUST_USER_SIZE / COPY_FIXED / COPY_UNBOUNDED /
  LEAK_POINTER / LEAK_CONTENT / WRITE_FUNCTION_POINTER / CALL_INDIRECT。
- 训练闭环接入：GOLD 8 题（全带 binary）即 curriculum；lab13（有 .c）为
  金标准交叉验证「IDA 证据 vs source 真值」；comparator 的
  TARGET_BEHAVIOR 层 required 证据（SOURCE/BINARY_INTERNAL_ACTION_FLOW）
  由此层供给——BinaryIR.target_actions 直接喂
  `analyze_heap_source(behavior_profile=...)`（ChallengeBehaviorProfile schema 已就绪）。
- 纪律：函数名只是弱证据（menu_role_hint 标注为 hint）；结论必须由
  CALL/数据流证据支撑，不足记 UNKNOWN。

### VNext.3 — Evidence / Hypothesis / Primitive Graph
- Evidence Record（已建雏形 `CallsiteEvidence`）：单条可引用事实
  （指令地址/调用者/参数来源/post-state/confidence/source）。
- Hypothesis 协议：H(support/against/confidence) → 生成最小实验（EXP 片段
  在 sandbox 运行）→ CONFIRMED/REJECTED 更新。禁止无证据下结论。
- Knowledge Graph：Function/Object/ChunkHandle 节点 +
  calls/reads/freed_by/allocated_by/accessed_by/modified_by 边；
  生命周期非法迁移（FREE→SHOW = UAF_READ candidate）自动产出 Hypothesis。
- Canvas 升级方向：画布 = KG 的 UI 投影；点击 UAF 标签显示 Why（证据链）。

### VNext.4~6（远期）
- VNext.4 GDB 自动验证（实验执行器）；VNext.5 Exploit Strategy Planner
  （Primitive Graph + glibc 版本裁剪路径）；VNext.6 EXP Generator
  （ExploitProgram AST → Pwntools/其它 renderer；诚实骨架原则；
  往返自检：生成的 exp 重喂 analyze_heap_source 必须 ROUND_TRIP_MATCH）。
- **首版已落地（2026-09-11）**：`features/synth/` 实现 VNext.3.1#9 原语图 +
  VNext.4 前半（规则驱动策略：ret2win/ret2plt/ret2libc/orw/srop/fmt/heap）+
  VNext.6 最小渲染器（诚实骨架 + `audit_exp` 往返自检）+ review_queue 沉淀与
  批量喂题 CLI。详见 `docs/exploit_synthesis.md`；运行时执行器（VNext.4 实验执行器）
  仍未接入，故 EXP 可利用性恒为 UNVERIFIED。

## 防自证与语料
每道题沉淀：ELF / BinaryIR / 语义标签 / 漏洞 / 原语 / 策略 / EXP /
runtime trace / 成败 → Pwn Foundation Dataset（与 heap-corpus 联动，
provenance 铁律不变）。生成物一律先进 review_queue。

---

# VNext.3 — Exploit Semantic Auditor（已落地确定性内核）

模块: `pwncraft/features/audit/`（`model.py` ExploitIR/Diagnostic/SourceSpan/Provenance ·
`values.py` 符号值域 · `extract.py` AST→IR + helper 内联 · `heap_state.py`
状态机+规则 · `quickfix.py` stdlib 快修 · `audit.py` 入口）。

已实现（第一层确定性内核，全部本地毫秒级）：
- **ExploitIR**：Interaction（SEND/SENDLINE/RECV/RECVUNTIL/RECVN/RECVLINE，含
  helper 内联展开与参数词边界绑定）/ PackOp（p32/p64/u32/u64）/ Hardcode /
  var→recv 长度 dataflow 种子。
- **符号值域**（VNext.3.1 #4）：Concrete/Symbol/Expr/Range/Unknown + join；
  状态机 index 解析遇 Symbol/Expr 即 UNKNOWN 事件，绝不猜。
- **SourceSpan + Provenance**（VNext.3.1 #1/#6）：诊断带 span；
  OBSERVED / DERIVED / MANUAL_ASSUMPTION 三来源。
- **堆状态机**：由 ChallengeBehaviorProfile 语义 + BehaviorFacts 重放 EXP 的
  helper 调用，产生 ALLOC/FREE/EDIT_AFTER_FREE/SHOW_AFTER_FREE 事件；
  helper 内联深度护栏 INLINE_DEPTH_LIMIT（VNext.3.1 #7）。
- **首批规则 8 条**：EXP_LEAK_001/002、EXP_LEAK_003（conf 0.55）、
  EXP_ARCH_001/002、EXP_PIE_001、EXP_HEAP_014（透传 POST_FREE_NULL_STORE
  证据链）、EXP_HEAP_021（UNKNOWN → Suggestion conf 0.61）、EXP_PARSE_001。
- **UNKNOWN ≠ FALSE 已代码化**：CLEAR_POINTER 有证 → Error；无证 → Suggestion；
  KEEP_DANGLING 有证 → 无诊断。
- **Quick Fix 应用器**（VNext.3.1 #3）：stdlib 文本补丁（span 定位 + 替换），
  LibCST 为可选加速器而非依赖；审计只建议不改动。
- 诊断字段：code/severity/confidence/message/evidence/suggested_fix/impact/
  span/provenance。
- 外部 helper 名单：EXP 中 import 的 helper 由 profile 提供语义也可审计。
- 测试: tests/test_exp_auditor.py / test_audit_values.py。

边界与后续：
- 树-sitter 增量解析（VNext.3.1 #2）= 编辑器层（typing 容错），需要 npm 依赖，
  与内核语义解耦；本内核消费 debounce 后的完整 AST。
- HeapCanvas 状态同步（VNext.3.1 #5）与 manual assumption 显式化 = 下一环。
- 扩展规则（VNext.3.1 #8）依赖 M2 的 size/参数角色证据，随后补。
- **原"第二层 AI"从正式路线删除**；若未来引入只作为 optional 插件。

## VNext.3.1 — Interactive Offline Auditor（九项）

1. SourceSpan + Provenance            ✅ 本轮
2. Tree-sitter 增量解析 → debounce → full AST pass   ⬜ 编辑器层
3. Quick Fix（stdlib 补丁先行, LibCST 可选）  ✅ 本轮
4. Symbolic Value Domain              ✅ 本轮
5. HeapCanvas 状态同步                ⬜ 下一环
6. MANUAL_ASSUMPTION / DERIVED / OBSERVED 来源系统 ✅ 本轮
7. helper 内联深度护栏                ✅ 本轮
8. 扩展 deterministic EXP rules       ⬜ 部分（依赖 M2 size/参数角色证据）
9. Exploit primitive graph            ✅ 首版（`features/synth/graph.py`，见 docs/exploit_synthesis.md）

### VNext.3.1A-completion — Provenance End-to-End + Assumption Branch Identity ✅ 本轮

`ProvenanceKind` 扩展七值成员（DERIVED_EXP/DERIVED_TARGET/DERIVED_ALLOCATOR/
OBSERVED_RUNTIME/USER_CONFIRMED_CORRECTION/MANUAL_ASSUMPTION；旧成员保留兼容），
CorrectionEngine 按意图盖戳（assumption → manual_assumption /
correction → user_confirmed_correction，字节级 provenance 可查）。
Assumption 分支血缘：`assumption_id / parent_snapshot_id(step-N) /
branch_kind=MANUAL_ASSUMPTION / trainable=False` 贯穿 episode + session
`assumptions` 登记 + `canvas_branch_kind` 暴露（Canvas 可明确显示
「当前 = 假设世界 ≠ 已证明目标真实状态」）。

**MANUAL_ASSUMPTION 语义锁死**：
```text
可驱动 hypothetical simulation → 可产生后续 hypothetical state
✗ 不允许升级成 DERIVED_TARGET
✗ 不允许进入 behavior learning
✗ 不允许作为漏洞已证实证据
✗ 不允许无标记参与训练 case
可参与 Auditor，但诊断 confidence=conditional 且
depends_on=[MANUAL_ASSUMPTION: <subject>]
```

### VNext.3.1B — Canvas Edit Intent Split ✅ 本轮

`HeapSession.correct(..., intent=)` 三意图：correction（默认，向后兼容，
USER_CONFIRMED_CORRECTION 管线含 learning）/ **assumption**（补丁应用+快照重建
让用户看到 what-if，但 episode 标 `MANUAL_ASSUMPTION` + `trainable=False`，
**禁止进入 learning**）/ exp_action（JS 侧路由到既有 safe 回写链）。
corrections 记录携带 intent/provenance；未知 intent 拒绝。
rpc_heap_correct 透传 intent；heap.js 编辑对话框新增意图选择。
验收: tests/test_canvas_intent_split.py（correction 行为不变 + assumption
隔离学习 + 快照可见推演结果 + 非法 intent 拒绝）。

**不变式**: Auditor 轻量状态机只做 EXP 语义验证；Canvas 物理真值永远只信
Python allocator engine（PhysicalMemory is the truth）——不建平行真值系统。

## VNext.3.2 — Advanced Static Reasoning

数据流/指针分析深化（argument origin、alias、field flow），全部确定性实现。

## VNext.4 — Exploit Planning / Synthesis（规则驱动, 非 LLM）

TargetBehavior（actions + behavior facts + glibc 版本）→ Primitive Graph
（UAF → tcache freelist manipulation → arbitrary allocation → overwrite）
→ 按版本裁剪路径（2.23 hook / 2.31 tcache / 2.35+ FSOP/exit_funcs）
→ Strategy → EXP IR → renderer。判定全部来自确定性证据。
