# v0.10.2 Validation

## Automated

- `QT_QPA_PLATFORM=offscreen python -m pytest -q`
  - `195 passed, 1 skipped`
- `python -m ruff check pwncraft tests artifacts/ui_audit/render_v0102.py artifacts/ui_audit/render_overlap_v0102.py artifacts/ui_audit/render_reuse_v0102.py`
  - `All checks passed!`

Coverage added for:

- no overlap separator/extra card gap;
- normal free/reallocation reuse keeps only the new chunk colour and creates no overlap region;
- concurrent House-style views and cross-chunk overflow evidence still enable exploit-overlap recolouring;
- partial overlap recolours only the physical intersection inside the chunk body;
- Pwndbg marker command echo is excluded from the captured snapshot;
- live Pwndbg snapshot updates the current HeapViz step while both old control tabs remain absent;
- runtime-pair discovery, in-place patch/backup, verification rollback, literal `$ORIGIN`, versioned libc `DT_NEEDED`, and `wsl.exe --exec` argv preservation;
- pinned Pwndbg version, asset SHA256 and WSL launch command.

## Real WSL patchelf probe

A freshly compiled x86_64 ELF was copied beside the current WSL loader and libc, then passed through `auto_patch_elf()` from Windows Python.

Verified authoritative outputs:

- rewritten original executed and printed `pwncraft-patchelf-ok`;
- interpreter: `/mnt/c/.../ld-linux-x86-64.so.2`;
- rpath: `$ORIGIN`;
- needed: `libc.so.6`;
- microsecond timestamp backup was created.

The temporary probe directory was removed after verification.

## Real pinned Pwndbg probe

- Downloaded the official `pwndbg_2026.07.29_x86_64-portable.tar.xz` through `PwndbgManager`.
- Verified the pinned SHA256, extracted it to `$HOME/.local/share/pwncraft/pwndbg/2026.07.29`, and confirmed `is_installed() == True`.
- Launched the portable Pwndbg against a fresh x86_64 malloc probe; it loaded 199 commands under GDB 17.2.
- `heap --count 128` returned the allocated `0x30` chunk at `0x555555559290`; the app parser recovered tcache/fastbin/unsorted/smallbin/largebin sections and all three heap records.
- The temporary runtime probe was removed; the requested pinned Pwndbg install remains available to the GUI.

## UI audit (1600 × 1000)

- Normal `A -> free -> B` reuse: only B is rendered in its stable normal colour; no overlap block or stale-A colour remains.
- Partial B/C physical intersection: only the intersecting chunk-body block uses overlap colour; no middle overlap strip/button.
- Heap canvas scroll range: horizontal `0`, vertical `0`.
- Bin/Show canvas scroll range: horizontal `0`, vertical `0`.
- Splitter sizes: EXP/visual `[550, 1022]`; Physical/BinShow `[755, 252]`.
- Pwndbg workspace fits drop zone, compact actions, terminal, command input and live diff without a page scrollbar.

Artifacts:

- `artifacts/ui_audit/heap_normal_reuse_v0102_windows.png`
- `artifacts/ui_audit/canvas_normal_reuse_v0102_windows.png`
- `artifacts/ui_audit/heap_overlap_blocks_v0102_windows.png`
- `artifacts/ui_audit/canvas_overlap_blocks_v0102_windows.png`
- `artifacts/ui_audit/pwndbg_linked_workspace_v0102_windows.png`
- `artifacts/ui_audit/render_overlap_v0102.py`
- `artifacts/ui_audit/render_reuse_v0102.py`
- `artifacts/ui_audit/render_v0102.py`

## Remaining runtime constraint

The automatic portable installer currently supports x86_64 WSL. Other WSL architectures fail with an explicit unsupported-architecture message rather than installing the wrong asset.
