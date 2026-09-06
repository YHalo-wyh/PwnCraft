# cycle-0-bootstrap-invalidated

状态: **INVALIDATED** 2026-09-03（协议所有者指令，TRAINING_PROTOCOL v1.1/v1.2）。
本目录为完整历史归档，不删除、不覆盖。

## 归档内容（全部保留原件）

- `resolver.py.pre` — 已作废 patch 应用前的 resolver 原始状态
- `cycle-1.patch` — 已作废的 patch diff（PROMPT_SYNC 硬编码负向判断版）
- `test_contract_prompt_sync_vs_output.py` — 该 patch 的合成测试（随 patch 一并作废）
- `reports/babyheap-divergence-report.v1.json` — bootstrap case (babyheap) 的 v1 comparator 报告
- `reports/lab13-divergence-report.before.v2.json` / `.after.v2.json` — v2 comparator 报告
- 旧 comparator 版本（v1=`autocorrect/comparator.py`, v2=`autocorrect/comparator_v2.py`）保留在 autocorrect/ 供审计

## 作废原因（协议所有者裁定）

1. **Analyst 污染**: babyheap 轮的期望分析在生成前已接触 PwnCraft 偏差信息，
   不得作为严格 held-out 评测样本。
2. **comparator v0/v2 只比较语义结果，未比较 evidence/provenance**: 「答案碰巧正确
   但理由错误」（show 的 SEMANTIC_MATCH/EVIDENCE_DIVERGED）未被识别为第一偏差，
   导致 patch 目标选错（选了 delete 而非 show）。
3. **patch 实现形态违反 v1.1 §C**: 「recvuntil(常量)+未用 ⇒ 必然 PROMPT_SYNC」
   属硬编码负向判断，不是 evidence-based 分类。

## 处置

- resolver.py 已恢复至 pre-patch（364 passed 基线）。
- v1.1/v1.2 语义下的第一轮正式训练编号为 **cycle-1**
  （目标: lab13 `show` 的 SEMANTIC_MATCH / EVIDENCE_DIVERGED）。
