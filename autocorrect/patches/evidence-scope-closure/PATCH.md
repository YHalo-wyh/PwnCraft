# EVIDENCE-SCOPE-CLOSURE (2026-09-05)

范围: 仅 comparator 证据责任校正。recognizer 冻结 (r4); locked truth 文件零改动
(truth_id 未变: lab13 060bebfe... / note2 2055bd70...)。

## Evidence Ownership Schema (comparator_v4.1)

| 层 | required_any | optional_corroborating |
|---|---|---|
| HELPER_CONTRACT | EXP 侧证据 (EXP_PROMPT_SEND_FLOW / EXP_CALLSITE_DATAFLOW / EXP_WRAPPER_DATAFLOW → STRUCTURAL_BODY/ALIAS 级) | SOURCE/BINARY_MALLOC_FLOW (dataflow_strong) — 缺失仅记录 |
| TARGET_BEHAVIOR | SOURCE_INTERNAL_ACTION_FLOW / BINARY_INTERNAL_ACTION_FLOW | EXP_COMMENT_NARRATIVE |
| ALLOCATOR | 已确认 target actions → 引擎事件 | — |
| PHYSICAL_MEMORY | allocator/write 动作 → 物理字节真值 | — |
| CANVAS | 禁止作为任何上游层的 truth evidence | — |

expected_truth 的 evidence_tier 读取时经 ownership 映射 (tier≥binary 的部分
降级为 optional_corroborating), truth 文件本身不修改。

## 结构变更
- comparator_v4 重构为层函数 (_LAYERS) + 共享 ctx; 新增 diagnose_layers()
  (collect_all, 无早停) 输出每层 {status, semantic_status, evidence_status,
  missing_required, optional_missing}; compare() 保持早停 first-divergence 纪律。
- 修复: collect_all 模式下 first_divergence 必须取最早偏差 (此前被后续层覆盖)。
- adapter 恢复公共 run_analyzer() (analysis-only, 测试/probe 用)。
- 合成测试 tests/test_evidence_scope.py T5/T6/T7; 原 T1-T4 全部保持通过。

## 验收结果
1. create(size) EXP 证据足 → helper MATCH (binary tier 仅 optional_missing) ✓
   (T5 合成 + lab13 create/edit 真实 MATCH)
2. malloc×2 在 TARGET_BEHAVIOR 层显式 DIVERGED, missing_required=
   [SOURCE_INTERNAL_ACTION_FLOW, BINARY_INTERNAL_ACTION_FLOW], 未被 helper 吞掉 ✓
   (T6 + lab13 diagnose)
3. note2 (无 source truth): newnote/deletenote MATCH, req_miss=[], first
   divergence = shownote 语义 (真实缺口) ✓ (T7 + 真实 case)
4. binary/source evidence 完整保存于 truth (lock 校验通过) 且以
   optional_missing 形式出现在每层报告 ✓
