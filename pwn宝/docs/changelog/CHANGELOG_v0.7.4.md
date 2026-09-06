# v0.7.4 - Heap AI 激进晋升与学习报告

## 改进

- 解释并修正“严格重放通过但没有晋升”的体验：默认仍保持 `2 个独立 case + holdout + 0 负样本`，避免把 Qwen 的单题误判污染到无 AI 静态识别。
- 新增可显式开启的激进晋升策略：
  - `--promotion-mode strict`：默认保守策略。
  - `--promotion-mode aggressive`：严格 replay 已证明的 helper 规则可按单 case、无 holdout 快速启用。
  - `--promotion-mode global-now`：显式的一例全局晋升模式，仍要求 strict replay 证明候选会真实改变 Heap IR。
- 新增可调门槛：
  - `--promote-threshold N`
  - `--promote-without-holdout`
  - `--promotion-confidence X`
- `AIKnowledgeStore.review_rule_candidate()` 支持可配置 positive case、holdout 和 rejected case 门槛，并在返回状态中给出 `blocked_by` 原因。
- corpus 批处理新增 `aggressive_learning_report.json`：
  - 汇总 strict preview accepted/rejected、feedback compiled、rule enabled/pending、over_budget、offline/model 等状态。
  - 记录未晋升原因，例如 `promotion_positive_cases`、`promotion_holdout`、`strict_replay_rejected`。
  - 明确 rejected/over_budget 只作为负反馈、提示词和静态分析 gap，不直接改 chunk/bin/画布事实。

## 推荐训练命令

```powershell
python -m pwnbao.tools.heap_ai_corpus artifacts\heap_ai_writeups\ruanan_finals_v1\manifest.json `
  --output artifacts\heap_ai_corpus\ruanan_finals_v1_ai_v8_aggressive `
  --knowledge artifacts\heap_ai_corpus\ruanan_finals_v1_knowledge.sqlite3 `
  --with-ai --auto-review-proven --promotion-mode aggressive --no-resume
```

如果你想手动更猛：

```powershell
python -m pwnbao.tools.heap_ai_corpus artifacts\heap_ai_writeups\ruanan_finals_v1\manifest.json `
  --output artifacts\heap_ai_corpus\ruanan_finals_v1_ai_v8_global_now `
  --knowledge artifacts\heap_ai_corpus\ruanan_finals_v1_knowledge.sqlite3 `
  --with-ai --auto-review-proven --promotion-mode global-now --promote-threshold 1 --promote-without-holdout --no-resume
```

## 边界

- AI 仍不能直接改堆图；只能提出 EXP 语义 IR 校正。
- 主图仍由严格 allocator replay 重新生成。
- Pwndbg observed 仍高于 AI 推断。
- 利用意图、注释、House 名称不会被晋升为 allocator 事实。
