# v0.13.2 Validation

## Commands

```bash
python -m ruff check pwnbao tests
QT_QPA_PLATFORM=offscreen python -m pytest -q
QT_QPA_PLATFORM=windows python -m pwnbao.tools.ui_audit_v013
QT_QPA_PLATFORM=offscreen python -m pwnbao.tools.performance_audit_v013
python3 -m pwnbao.tools.pwndbg_interactive_performance
```

## Recorded outputs

- Tests: 266 passed, 1 skipped.
- Fork registry: `artifacts/ui_audit_v013/pwndbg_command_regression.json`, loaded 205, missing `[]`.
- Standalone screenshot/capture: `pwndbg_fork_standalone.png` / `pwndbg_fork_standalone.ansi`.
- Embedded/CJK/color screenshots: `pwndbg_embedded_*.png`, `pwndbg_text_spacing.png`, `pwndbg_slash_native.png`, `pwndbg_mogai_workspace.png`.
- Forced-color capture: `pwndbg_mogai_color_forced.ansi`; contains native SGR color sequences while `disable-colors` is off.
- Heap screenshots: `heap_inline_edit.png`, `heap_invalid_edit.png`, `heap_extent_overlap_edit.png`, `heap_overflow_blank_editor.png`, `heap_underflow_subject.png`, `heap_plus_reflow.png`.
- Performance: `performance.json`, `pwndbg_interactive_performance.json`.

## Windows packaging

- Executable: `dist/pwn宝.exe` (60,256,304 bytes).
- SHA-256: `b589fb93dbd8ee82d6a995d4fad619a8c812589f981ed1681b37d2269ff677e8`.
- Archive inventory: `artifacts/ui_audit_v013/pyinstaller_archive_listing.txt`; includes `third_party\pwndbg-mogai\UPSTREAM_COMMIT` and `launcher.sh`.
- Smoke launch: `artifacts/ui_audit_v013/exe_smoke.json`; frozen bootloader/application processes remained alive after 5 seconds and were then terminated by the harness.
- Frozen WSL smoke: `artifacts/ui_audit_v013/frozen_wsl_smoke.json`; `wsl.exe` returned 0 and resolved both `/home/wyh/bin/pwndbg` and `/home/wyh/.local/bin/pwndbg-mogai` without `0xc0000142`.
