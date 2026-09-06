# PwnCraft AI 自动校正闭环 (autocorrect)

协议: [TRAINING_PROTOCOL.md](TRAINING_PROTOCOL.md)（LOCKED, **v1.1 修订 2026-09-03**）。
比较器: `comparator_v3.py`（六元组 HelperContract 比较 + provenance 独立验证 + 1:N allocator events）。
回归: `regression.py` 版本化基线（`<label>__<patch_id>` 永不覆盖，accepted_truth 不随 patch 刷新）。

## 命令

```bash
python loop.py generate <case> --label pre-patch   # Phase B: PwnCraft 原始输出 -> generated/<label>/
python loop.py diverge  <case> --label pre-patch   # Reviewer: expected_truth vs generated (v3)
python loop.py baseline <case> --label pre-patch --patch-id none --intentional-delta op_sequence
python loop.py regress                             # 对每个 case 的全部基线版本报告对齐状态
```

## v1.1 关键语义

- HelperContract 比较六元组: semantic / argument_roles / confidence / evidence_type /
  evidence / provenance。
- `SEMANTIC_MATCH / EVIDENCE_DIVERGED`（答案对、理由错）= 合法 first divergence。
- PROMPT_SYNC 必须 evidence-based: 未用 recvuntil(常量)=candidate，紧邻
  send(parameter)=strong，prompt 文本形状=弱证据；禁止硬编码必然判断。
- 1:N allocator events: `create = malloc(0x10)+malloc(size)`，
  `delete = free(content)+free(struct)`（two free calls，**禁称 double_free**）。
- 首个严格 first divergence（lab13 pre-patch）: `show` — SEMANTIC_MATCH /
  EVIDENCE_DIVERGED（report: `cases/.../divergence_report.pre-patch-v3.json`）。

## 历程

- cycle-0 (bootstrap, babyheap): 发现 allocate 契约缺失与 free→SHOW；因 Analyst
  污染降级为 bootstrap，不作 held-out。
- cycle-1 (v0 判定, 已作废): 以 delete 语义偏差为目标打过 patch，经 owner 修正后
  revert（`patches/cycle-1/` 保留完整 checkpoint 与 diff），等待重编号。
- 当前状态: resolver 处于 pre-patch（364 passed），lab13 严格第一偏差已锁定，
  等待协议所有者批准 cycle-1 重编号后按 v1.1 §C 形态重新实施修复。
