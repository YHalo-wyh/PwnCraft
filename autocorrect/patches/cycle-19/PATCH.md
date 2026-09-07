# Cycle-19 · SCTF 2026 slang · additive write -> reviewed control plan

Status: **ACCEPTED candidate pending final branch/main gate** · 2026-09-07

## First divergence

Cycle-18 ended at an exact `derived_static` additive 64-bit write (`0x404018 += -205200`). PwnCraft still had no evidence-preserving layer that could combine that primitive with reviewed binary/target facts without guessing a GOT symbol from an address.

## Locked truth

Official SCTF material reviews `0x404018` as `puts@GOT`, states the generated ELF is `-no-pie`, uses a writable GOT route, resolves `puts` before the write, and gives the only numeric relation needed here: `system - puts = -0x32190 = -205200`.

The cycle intentionally records the **relative symbol delta** rather than inventing absolute libc symbol offsets.

## Generic patch

`pwncraft.features.audit.reviewed_chains` adds `AdditiveControlTargetPolicy` + `derive_additive_control_plan()`.

Promotion requires exact agreement on:
- additive primitive kind;
- address and width;
- reviewed target identity;
- writable + fixed-address target;
- reviewed current-value resolution;
- exact reviewed relative delta or a mutually consistent pair of reviewed symbol offsets.

Output remains `derived_static`, `runtime_observed=false`.

## Precision regressions

Negative cases lock:
- wrong write address;
- wrong delta;
- unresolved current value;
- non-fixed target;
- inconsistent/missing target evidence.

## Not claimed

This cycle does **not** prove the later `/bin/sh` trigger executes `system`, does not claim a shell/flag, and does not infer symbol identity from `0x404018` alone.

## Next divergence

`slang` is sufficiently closed for now. Breadth takes priority: continue UBW allocator-state reasoning, heapMage glibc-2.39 semantics, and new stack/format cases.
