# v0.10.1 Validation

## Automated

- `QT_QPA_PLATFORM=offscreen python -m pytest -q`
  - `187 passed, 1 skipped`
- `python -m ruff check pwncraft tests artifacts/ui_audit/render_v0101.py`
  - `All checks passed!`

## UI audit (1600 × 1000)

- Replay: `A/B` allocation, size-field overflow, free/reuse, `C/D` overlapping views.
- Heap canvas scroll range: horizontal `0`, vertical `0`.
- Bin/Show scroll range: horizontal `0`, vertical `0`.
- Splitter sizes: EXP/visual `[550, 1022]`; Physical/BinShow `[755, 252]`.
- Full screenshot: `artifacts/ui_audit/heap_mesh_overlap_v0101_windows.png`.
- Canvas screenshot: `artifacts/ui_audit/canvas_overlap_intervals_v0101_windows.png`.
- Replay script: `artifacts/ui_audit/render_v0101.py`.
