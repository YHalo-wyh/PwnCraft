# Cycle 37 — Offline ELF Artifact Provider

## First divergence

Cycles 34–36 exposed one shared evidence gap across otherwise unrelated lanes:

- UBW can reach the exact `libc+setcontext` dispatch target, but target-libc instructions are not inspectable through the GitHub text connector;
- heapMage can prepare wide-data state, but numeric `system` / `_IO_2_1_stderr_` symbols require the exact target libc;
- CCTF pwn3 has a symbolic `puts@GOT -> system` plan, but exact relocation address, runtime writability and libc symbol offsets require the ELF/libc artifacts.

The correct patch is not to copy community magic addresses into truth.  The
missing layer is a deterministic local artifact provider.

## Patch

`pwncraft.core.elf_artifact_provider` adds an offline-first evidence contract and
collector backed by local GNU binutils:

- exact artifact SHA256 and artifact identity;
- ELF class/type/machine/entry point;
- symbol definitions from `readelf -Ws` with versioned-name normalization;
- relocations from `readelf -rW`;
- PT_LOAD and PT_GNU_RELRO ranges from `readelf -lW`;
- bounded instruction windows from `objdump -d --start-address/--stop-address`.

The provider exposes exact queries for:

- defined symbol resolution and runtime symbol address calculation;
- relocation lookup by symbol;
- executable-range checks;
- conservative runtime-writability checks (`W` PT_LOAD and not GNU_RELRO);
- bounded instruction-window retrieval.

Full-library disassembly is intentionally not the default: callers must request
explicit windows, capped at 0x4000 bytes each and 32 windows per collection.

## Safety / truth boundary

This layer emits artifact facts only.  It does **not** infer:

- a vulnerability from the presence of a symbol or relocation;
- GOT hijack viability without a reviewed format/write primitive and runtime value;
- stack pivot/control transfer from a `setcontext` symbol;
- Apple2/FSOP from `_IO_*` names;
- an unrestricted arbitrary allocation from one writable tcache entry.

Exact binary facts can now enter PwnCraft locally even when a remote connector
cannot decode ELF bytes.  Downstream exploit-state promotion remains separately
gated.
