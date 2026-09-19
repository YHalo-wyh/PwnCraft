# Cycle 41 — UBW target-libc setcontext restore semantics

## First divergence

Cycle 34 could prove that the reviewed stdout/FILE/wide-vtable chain reaches the exact target `libc_base + 0x4a960`, named `setcontext` by the official UBW EXP. It deliberately stopped there because a symbol identity is not evidence for how that specific libc restores registers or whether a ret-based continuation is runtime-valid.

The missing layer was therefore not another FSOP/House-of-* recognizer. It was an artifact-bound instruction-semantic gate between an exact indirect-call target and a context-restore/control-flow claim.

## Pinned evidence

The official SCTF 2026 UBW artifacts were pinned to the official repository commit. A one-time CI evidence collection on the exact official files established:

- libc SHA256 `d8db8739a1633c972cec6a4fe0566bdcec6fd088f98723492ab0361f66238f75`;
- UBW SHA256 `34ba9b25d40ce8ff2beacd236a30a5367c2cdfb5ba06618642e5980f8c2cdde0`;
- `setcontext@@GLIBC_2.2.5` at libc offset `0x4a960`;
- `setcontext+0x04`: preserve incoming `rdi` with `push`;
- `setcontext+0x20`: recover that value into `rdx`;
- `setcontext+0x3d`: `rsp <- [rdx+0xa0]`;
- `setcontext+0x5f/+0x6b`: explicit shadow-stack runtime branch;
- ordinary path `+0x126/+0x12d/+0x14e`: load `[rdx+0xa8]`, push it and return.

The temporary networked CI collection step was removed immediately after locking these facts. The normal training gate remains offline with respect to challenge artifacts.

## Patch

`features/audit/reviewed_setcontext_restore.py` consumes:

1. the previous exact reviewed `setcontext` dispatch target;
2. the previous reviewed FILE field state;
3. one exact `ElfArtifactSnapshot` with matching SHA256 and bounded instruction evidence;
4. an explicit reviewed calling-convention/dispatch-argument identity gate.

It verifies the target symbol and exact instruction addresses/operands before emitting only:

- `reviewed_setcontext_frame_restore_semantics`;
- `reviewed_setcontext_frame_values_bound`.

For UBW this binds the original fake-FILE dispatch argument to the target-libc frame base, the exact restored RSP to the reviewed `FILE+0xa0 = widep`, and the ordinary-path continuation to reviewed `FILE+0xa8 = libc+0x12dfba`.

## Hard boundary

The target libc contains both a shadow-stack-aware path and an ordinary `push continuation; ret` path. Cycle 41 records that branch as unresolved at runtime.

Therefore this cycle does **not** promote:

- existence of the ordinary path -> runtime ordinary-path selection;
- restored `RSP` / continuation values -> executed `ret` gadgets;
- `libc+0x12dfba` -> successful `add rsp,0x38; ret`;
- `wide+0x38/+0x40` -> successful `pop rsp; ret` pivot;
- any of the above -> ROP/ORW, shell, or flag retrieval.

The next UBW layer must independently bind runtime mitigation state before composing those exact artifact gadgets.
