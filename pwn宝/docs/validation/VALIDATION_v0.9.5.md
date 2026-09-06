# pwn宝 v0.9.5 验证记录

## Sunshine corpus

```text
EXP candidates: 52
syntax valid: 52/52
heap_model_ready: 39
partial / needs challenge behavior profile: 10
excluded non-heap: 3
per-file replay exceptions: 0
```

产物：

- `artifacts/sunshine_ast_v095/REPORT.md`
- `artifacts/sunshine_ast_v095/report.json`
- `artifacts/sunshine_ast_v095/cases/*.json`

## 回归

```bash
python -m pytest -q
python -m ruff check pwnbao tests
python -m pwnbao.tools.sunshine_ast_corpus "/mnt/c/Users/WYH/Desktop/sunshine 附件" \
  --output artifacts/sunshine_ast_v095
```

重点新增回归：

- 偶然 heap 子串不会污染 API profile；
- transitive helper bounded inlining；
- literal-choice variadic dispatcher；
- JSON action 映射；
- embedded JavaScript object lifetime；
- corpus inventory 与逐 EXP replay artifact。
