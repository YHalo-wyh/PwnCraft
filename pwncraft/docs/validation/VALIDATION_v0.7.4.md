# v0.7.4 验证记录

## 已执行

```powershell
python -m unittest tests.test_ai_corpus -v
python -m ruff check .
python -m compileall -q pwncraft tests run_pwncraft.py build.py
python -m unittest discover -s tests -p "test_*.py" -v
```

## 结果

- `tests.test_ai_corpus`：19 项通过。
- `ruff`：All checks passed。
- `compileall`：通过。
- 全量回归：130 项通过。

## 新增覆盖

- 默认 strict 仍只在独立 holdout 证据满足后启用全局规则。
- `promotion_mode="aggressive"` 下，strict replay 已证明的 helper rule 可在单个 case 后启用。
- 激进规则启用后可被无 AI 的 `analyze_heap_source(... learned_rules=...)` 使用。
