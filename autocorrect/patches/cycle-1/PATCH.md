# cycle-1 patch (recognizer-2026.09-r3)

目标: lab13 `show` 的 SEMANTIC_MATCH / EVIDENCE_DIVERGED —
"错误的 PROMPT_SYNC 被当成 OUTPUT_DATA_FLOW" (TRAINING_PROTOCOL v1.2 §H)。

## 变更 (最小集, 仅证据分类)

1. resolver.py `_structural_contract`: recv 证据判定加数据流条件 —
   返回值被丢弃的 recv 族调用 (裸语句) 不再置 recv=True。
   丢弃的 recvuntil = PROMPT_SYNC (仅同步/绑定); 丢弃的 recv/recvn/recvline 无数据流;
   仅被消费的 (赋值/返回/打印/进入计算) recv 结果构成 OUTPUT_DATA_FLOW, 可证 SHOW。
   FREE/DELETE 不依赖该标志 (§H)。
2. analyzer.py: RECOGNIZER_REVISION r2 → r3 (可追溯性)。

## 禁止事项遵守

- 未新增/扩充任何函数名别名表; 未实现 candidate_operation 提升;
  未顺带修 1:N allocator; 无题目/hash/地址特判。
- delete 契约变化 (show→delete) 来自预存分支恢复可达, 记录为 downstream effect
  (divergence_report.cycle-1-after.json)。

## 测试

- tests/test_contract_output_dataflow_evidence.py: 7 synthetic (R1-R4 + sanity),
  pre-patch 3 红 4 绿, post-patch 7 绿。
- 项目全量: 371 passed, 1 skipped (pre-patch 基线 364+1)。

## checkpoint / revert 路径

- resolver.py.pre / analyzer.py.pre (本目录)
- revert: cp resolver.py.pre ../pwncraft/pwncraft/features/heapviz/contracts/resolver.py 等
