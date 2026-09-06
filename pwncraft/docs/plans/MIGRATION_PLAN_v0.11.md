# pwncraft v0.11 Internal Migration Plan

## Baseline frozen before implementation

- Preserve `PhysicalMemory -> typed allocator reads -> HeapSnapshot` and every v0.10 truth invariant.
- Current automated baseline: 195 passed, 1 skipped.
- Semantic benchmark baseline: 60/60 whole-case pass.
- Sunshine baseline: FULL_REPLAY 23, PARTIAL_REPLAY 18, MODEL_READY 2, PARSE_ONLY 9, SEMANTIC_VERIFIED 0; MODEL_READY-or-better 43/52 (82.69%).
- Official Pwndbg remains pinned to 2026.07.29 and is never modified in place.

## Migration boundaries

1. Keep HeapViz allocator/engine behavior unchanged except explicit integration adapters.
2. Replace `PwndbgBridgePanel` with a thin compatibility import over a new debugger workspace package.
3. Build a true WSL PTY transport using a small Linux `pty.openpty()` relay. `wsl.exe` only carries relay bytes; GDB/Pwndbg owns a real controlling TTY.
4. Separate terminal responsibilities into transport, session state, ANSI screen/emulator, Qt renderer and machine protocol decoder.
5. Load a project-owned, Qt-free GDB/Pwndbg Python extension alongside the official portable distribution.
6. Carry structured host messages in framed OSC/DCS control sequences which are removed before terminal rendering.
7. Populate `/` palette primarily from the live Pwndbg command registry; local Tutor aliases only map to namespaced `pwncraft-*` commands.
8. Frame facts come from GDB selected-frame/unwinder/symbol/debug information. `[RBP+8]` is exposed only after explicit frame-pointer consistency checks.
9. Operation history records user-typed, slash and explicit history replay commands only. Reinsert changes the editable terminal line; it never claims to roll back inferior state.
10. Runtime calibration remains `CALIBRATED`, debounced and hidden behind a compact validation affordance.

## Implementation phases

### P0 transport and terminal

- Add `core/terminal/{transport,wsl_pty,protocol,ansi,session}.py`.
- Add project-owned WSL PTY relay with resize and interrupt control packets.
- Add `gui/debugger/terminal_widget.py`; remove command QLineEdit and Send button.
- Validate isatty, Readline editing/history/completion, Ctrl+C and terminal resize against the pinned Pwndbg.

### P0 extension and current truth

- Add `pwndbg_ext/` bootstrap, compatibility, protocol, translations, state/frame and command modules.
- Emit hello/version/catalog/prompt/session/stop/frame/heap/error messages.
- Add Tutor commands `pwncraft-frame`, `pwncraft-frames`, `pwncraft-ret`, `pwncraft-rbp`, `pwncraft-stackof`, `pwncraft-safe` without overriding GDB/Pwndbg names.
- Do not create previous-state, Before/After or exploit-hypothesis models.

### P0 discovery and history UI

- Add in-terminal slash overlay with live filtering, Chinese presentation translations, registry fallback, argument hints and keyboard selection.
- Add 75/25 terminal/history splitter, bounded user-only `OperationEntry` history, search, reinsert and explicit rerun.
- Keep reverse execution disabled unless real GDB recording is explicitly enabled and probed.

### P1 runtime bridge and paths

- Replace text markers with structured machine messages; retain text parsing only as fallback.
- Debounce heap snapshots on stop/manual sync and keep detailed diff collapsed.
- Fix Windows/WSL path conversion before host-specific `Path.resolve()` and cover Windows, spaces, Chinese, WSL and Linux paths.

### P1 analyzer/corpus

- Add deterministic analysis profile hooks for common pwntools args branches and record precise next-level blockers.
- Do not alter unknown to known without static proof, user profile or runtime calibration.
- Re-run corpus and report honest status; 90% is a target, not permission to weaken semantics.

## Acceptance evidence

- Automated: pytest, Ruff, 60-case semantic benchmark and Sunshine corpus report.
- Native: pinned Pwndbg PTY smoke, readline Tab/history, Ctrl+C, resize, registry catalog, frame-pointer and frameless C harnesses, official command smoke and extension-failure fallback.
- UI: six 1600x1000 screenshots required by the v0.11 specification.
