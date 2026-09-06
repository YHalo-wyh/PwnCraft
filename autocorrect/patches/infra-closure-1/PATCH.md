# INFRA-CLOSURE-1 (2026-09-05)

范围: 仅训练框架/管线基础设施。recognizer 语义冻结 (r4 不变, 语义指纹逐位一致)。

## 变更
- P0-2 单权威运行: adapter 重写 (ONE HeapSession.load 派生全部 artifact),
  run_manifest.json (run_id/exp+binary+libc sha/revision/profile id+revision/
  memory_revision/snapshot_id), 所有 sidecar 同 run_id, comparator RUN_IDENTITY
  门禁拒绝混 run。
- P0-1 op_id 对齐: canonical/step 全部以 op_id 关联 (value/init 属合法 canonical
  全集); TARGET_BEHAVIOR/ALLOCATOR/BINS 全走 op_id; 反位置合成测试
  tests/test_infra_closure.py T1/T1b。
- P0-3 TARGET_BEHAVIOR 真实层: target_behavior.json artifact (当前管线 identity
  mapping + internals_not_modeled 显式 unknown); 与 ALLOCATOR (动作→事件转换)
  拆为两个比较函数; T3 锁定两层不同失败形态。
- P0-4 physical_memory.json + snapshots.json 正式 artifact (physical objects 与
  stale typed/logical views 分离; memory regions/provenance 通道); comparator
  层序: ...TargetBehavior→Allocator→PhysicalMemory→Bins→Snapshot→CanvasTruth→
  RendererPlan。
- P0-5 canvas_model.py 更名 CanvasTruthModel (后端真值, 非 renderer 计划声明);
  heap.js IIFE 内新增 exportRendererPlan/rebuildAndPlan (复用 chunkLayout/
  chunkSizeTriple/cachedChunkGrid/coverageSpansFor/bodiesByChunk/allBinLayouts,
  零重算); node headless harness (renderer_plan_export.mjs, stub DOM + vm eval
  真实 renderer 源); 五项 special check 按 JS 实际约定校准 (header 单行两格=
  字节覆盖比较; extent 基准; overlap 字节区间; regime 感知 virtualization;
  top card 几何)。
- P1-1 truthregress 命令 (fresh authoritative run + strict comparator;
  accepted_cases.json 注册表, 当前为空=可执行性证明)。
- P1-2 truth lock: lock-truth 命令 (truth_id/content_sha256/schema_version/
  locked_at/analyst_input_hashes/truth_revision); generate 前强制校验。
- P1-3 六元组结构化比较 (semantic/argument_roles/confidence requirement/
  evidence predicates/evidence type/provenance); 自然语言 evidence 不参与相等
  判断; OUTPUT_DATA_FLOW 独立验证 py2 容忍 + 最小 def-use (赋值≠消费) (T4)。
- P1-4 原子 generate (tmp 目录→run_id 校验→atomic promote); 诚实文件名
  (snapshots.json=真实快照视图; bridge_steps.json=renderer 载荷)。

## 事故与恢复 (如实记录)
cmd_baseline/cmd_run 曾把 out_path 指向 case 根, 原子提升误将整个 case 目录
替换, 清除了 lab13/note2 的 expected_truth 与 divergence 报告。已从 review
bundle 副本恢复, truth_id 逐位复现 (060bebfe.../2055bd70...) 证明内容与锁定态
完全一致; 误置文件隔离于 cases/*/recovered_misdirected_promote/。
修复: _write_artifacts 提升防护 (仅允许 generated/<label>/), baseline/run/regress
不再写 sidecar。

## 验收
A 三 case artifact run_id 全 uniform ✓  B op_id 无 off-by-one (T1/T1b) ✓
C Target/Allocator 两真实层 (T3) ✓   D PhysicalMemory 接通 ✓
E truth↔plan 三 case MATCH (真实 heap.js 管线导出) ✓
F stability: 3 case 全 STABLE ✓    G truthregress 可执行 (2 case DIVERGED@HELPER_CONTRACT 如实) ✓
H 语义无变化: note2 post-infra 指纹与 cycle-2 基线逐位相同; lab13/babyheap 对
  最新基线 MATCH; recognizer_revision 恒为 r4; 项目全量 390 passed+1 skipped ✓

## 补遗 (同轮二阶段, owner 规格逐字核对后的缺口闭合)

1. physical_memory.json: 每 step 增加 memory_revision; physical objects 补
   provenance/regions/evidence_level/heap_offset/physical_range (全部取自
   bridge 载荷, 不发明)。
2. RendererPlan rows 增加 cells (同一 grid 对象的 word 半格字节区间, 零重算);
   bins_layout 以含 bins 的 step 验证真实填充 (babyheap step6=1 组)。
3. supersede-truth 命令 (P1-2 修订链): 锁定 truth 被证伪时, 旧版存为
   <stem>.revN.superseded.json (+revision_reason), 新版以 revision N+1 重新
   锁定 (truth_id 重算, supersedes 回链)。

## extent 基准事件 (truth 模型修正, renderer 确认正确)

五项 special check 在含真实 bins/overlap 的 step 上暴露: note2 phys_0003
(unlink 伪造 header, decoded=134336, extent=144) 的 CanvasTruthModel 按
decoded 建出 8397 行, 真实 JS 按 extent 建 5 行。P0-5 check#2 (extent 基准)
反过来抓住了 truth 模型自身违反该基准 — 已修正 (chunk_size = extent 优先),
renderer 无需改动。教训: CanvasTruthModel 是'应呈现什么'的模型, 同样要遵守
它所验证的规则。

## 复验结论 (最终)

- E: 三 case truth↔plan 全 MATCH (steps 4+6, 含 bins/overlap 持有步)
- F: 3 case STABLE; note2 post-infra digest = cycle-2 基线 digest
  (d4c156645c4c3091, 逐位相同) → H 语义零变化密码学证明
- 项目全量 390 passed + 1 skipped; infra 合成 5/5
