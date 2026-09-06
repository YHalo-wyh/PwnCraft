# pwn宝 v0.7.3 Validation

## Commands

- `python -m unittest discover -s tests -p "test_*.py" -v` → 129 tests OK
- `python -m ruff check .` → OK
- `python -m compileall -q pwnbao tests run_pwnbao.py build.py` → OK

## Local corpus run

- `python -m pwnbao.tools.heap_ai_writeups "C:\Users\WYH\Desktop\软安决赛" --output artifacts\heap_ai_writeups\ruanan_finals_v1 --kind local`
  - 12 heap cases
  - 62 helper candidates
  - generated `manifest.json`, `source_index.json`, `prompt_guidance.json`
- `python -m pwnbao.tools.heap_ai_corpus artifacts\heap_ai_writeups\ruanan_finals_v1\manifest.json --output artifacts\heap_ai_corpus\ruanan_finals_v1_static_v3 --knowledge artifacts\heap_ai_corpus\ruanan_finals_v1_knowledge.sqlite3 --no-resume`
  - 12/12 completed
  - 0 failed

## Static feedback result

- Before active-object edit rule:
  - `static_unmapped_call`: 3
  - operations: alloc 571, free 278, edit 108, show 85, copy 100
- After active-object edit rule:
  - `static_unmapped_call`: 0
  - operations: alloc 571, free 338, edit 132, show 91, copy 100

The operation increase is expected: `edit_bio` no longer stops analysis as unresolved, so later proven calls continue to replay.

## Qwen v7 probe

- `python -m pwnbao.tools.heap_ai_corpus artifacts\heap_ai_writeups\ruanan_finals_v1\manifest.json --output artifacts\heap_ai_corpus\ruanan_finals_v1_ai_v7 --knowledge artifacts\heap_ai_corpus\ruanan_finals_v1_knowledge.sqlite3 --with-ai --no-resume`
  - completed: 6
  - over_budget: 6
  - raw candidates: 4
  - strict accepted before new op-anchor gate: 1
  - strict rejected: duplicate IR / free_unknown
- After adding op-anchor gate:
  - `local.ruanan.traditional-Traditional.83065a44` candidate is rejected with `source=alloc, candidate=show`.

No Qwen candidate from this batch was promoted to a global deterministic rule.
