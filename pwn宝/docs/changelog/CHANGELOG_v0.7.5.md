# v0.7.5 - Qwen 提示词诊断、预算压缩与静态反哺

## 结论

- 本轮“没有晋升”的主要原因不是晋升门槛，而是候选质量：
  - v8：6/12 completed，3 个候选均被 strict replay 拒绝，6 个 over_budget。
  - v10：压缩 catalog 后 10/12 completed。
  - v11：minimal timeline 去重后 12/12 completed。
  - v13：加入负规则后 12/12 completed，0 over_budget，0 raw candidate，0 strict reject。
- Qwen 在短上下文小探针里能遵守“静态已正确则空返回”；在完整 EXP 上会被冗余 timeline、catalog wire schema 和利用语义诱导乱补。因此定性为“提示词/上下文组织为主，模型长上下文判断边界为辅”。

## 改进

- AI prompt 从 `pwnbao-heap-ai-v8-helper-first` 演进到 `pwnbao-heap-ai-v10-negative-rules`：
  - 明确“如果 static_analysis 已正确或 rationale 说 no change，必须返回空 proposals”。
  - 禁止把 `derive_value/leak/address math` 当 allocator op。
  - 禁止把 `heap_base+offset`、`index=3` 这类地址/说明写入 `chunk` 字段。
  - `replace_operation` 必须保留已有 `data/value`，避免丢失静态事实。
- 压缩 `heap_rule_catalog`：
  - 由重复长字段改成短字段 `id/args/need/place`。
  - 公共参数只列一次，catalog JSON 从约 2683 字符降到约 989 字符。
- minimal prompt timeline 去重：
  - 重复入口流程不再逐条塞给模型，改为首个 timeline 行 + `timeline_repeats`。
  - 两个原本 4.3K token 的样本被压回 3.3K 左右。
- wire-format 容错增强：
  - 规范化 Qwen 常见 role slip，例如 `{'name':'index'}` → `index`。
  - 支持把 `operation:{id,args,need}` 和 `operation:{op:{type,args}}` 这类错包转成 `heap_rule_call`，再交给 strict replay。
  - 修复 catalog rule 中 `index=0` 被当成缺失的问题。
- 静态识别反哺：
  - 新增保守菜单 helper 推断：
    - `choice=7` + 三参发送顺序 → `copy(src,dst,length)`。
    - `choice=4` + 一个 index 参数 + 无 recv → `free(index)`。
    - `choice=3` + 一个 index 参数 + recv → `show(index)`。
  - Analyzer 在发现此类 helper 后同步更新参数 roles，避免模板被旧参数名猜测覆盖。
- CLI 增加模型预算参数：
  - `--context-budget`
  - `--max-input-tokens`
  - `--max-output-tokens`
  - `--timeout`

## 推荐训练命令

```powershell
python -m pwnbao.tools.heap_ai_corpus artifacts\heap_ai_writeups\ruanan_finals_v1\manifest.json `
  --output artifacts\heap_ai_corpus\ruanan_finals_v1_ai_v13_negative_rules `
  --knowledge artifacts\heap_ai_corpus\ruanan_finals_v1_knowledge.sqlite3 `
  --with-ai --auto-review-proven --promotion-mode aggressive --no-resume
```

如果 LM Studio 已开更大上下文，可加：

```powershell
--context-budget 8192 --max-input-tokens 7680
```

## 边界

- 没有 strict replay accepted 的候选就不会晋升；这是正常的。
- “0 候选”在当前样本集里是好信号：静态识别已覆盖，Qwen 没有继续乱改图。
- 后续真正需要晋升的方向是新增 golden case，制造静态识别确实漏掉的 helper/dispatcher/corruption 语法，再让 Qwen 提出并通过 strict replay。
