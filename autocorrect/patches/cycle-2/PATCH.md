# cycle-2 patch (recognizer-2026.09-r4)

目标: note2 的 EXP_PARSE 第一偏差 — py2 print 方言导致 ast.parse 失败, 全下游不可用。

## 变更 (最小集)

1. 新增 pwncraft/features/heapviz/source_compat.py:
   parse_module_source() — 常规解析失败时, tokenize 引导的语句级改写
   (仅语句首 print 词法单元; 字符串字面量永不触碰; 行号保持) 后重解析;
   仍失败返回原始错误。rewrite_py2_print_statements() 为纯词法规则。
2. 接入 5 个模块级解析点: analyzer.py (analyze + partial-recovery probe),
   contracts/resolver.py (resolve + lower_source_calls), api_profile.py。
3. RECOGNIZER_REVISION r3 → r4。

## 禁止事项遵守

- 纯词法/方言级规则, 无题目名/hash/地址特判; py3 源路径完全不变
  (lab13/babyheap 指纹漂移仅 recognizer_revision 一维, 已核实)。
- 未顺带修 shownote/editnote 契约 (cycle-3 目标)。

## 测试

- tests/test_source_compat_py2_print.py: 8 synthetic (P1-P6), pre-patch 3 红 5 绿 → post 8 绿。
- 全量: 390 passed, 1 skipped (patch 当日 pre-patch 基线 375+1skip, 净增=本 patch 15 个测试中的 8 个 +
  cycle-1 的 7 个; 期间另有外部会话对 tests/ 的 +11 测试修改, 见汇报 STABILITY_REGRESSION)。

## 泛化 (probes, regression/probes_cycle-2.json)

- wheelofrobots: SyntaxError → valid, 8 契约/26 ops (GENERALIZATION_SUCCESS)
- hacklu-bookstore: SyntaxError → valid, 5 契约 (GENERALIZATION_SUCCESS)
- stkof (py3 对照): 不变 (规则对 py3 惰性)

## checkpoint / revert

- *.pre 三份 + diff; revert = cp 回原位并还原 r4→r3。
