# Cycle-21 · SCTF 2026 UBW · same-argument alias -> conditional double release

Status: **ACCEPTED candidate pending final branch/main gate** · 2026-09-07

## First divergence

UBW's official `merge(dst,src)` semantics are alias-sensitive. Existing helper/action abstractions could record realloc/free activity but did not preserve the key relation that `dst == src` makes the realloc source, subsequent strcat source, and explicit free refer to the same old allocation.

## Locked truth

Official writeup reviews the helper as approximately:

`new = realloc(arr[dst], combined); strcat(new, arr[src]); free(arr[src]); ...`

Official EXP invokes `merge(0, 0)`.

Therefore, **if realloc moves and frees the old allocation**, the same identity is:
1. released by realloc;
2. read again through the stale aliased `arr[src]` in strcat;
3. explicitly freed again.

The double release is deliberately conditional; the cycle does not state that realloc moved in every run.

## Generic patch

`AliasHelperPolicy` + `derive_alias_release_hazard()` require:
- explicit reviewed helper semantics;
- exact helper match;
- syntactically equal argument expressions;
- reviewed mapping of realloc-old / stale-read / explicit-free parameters.

It emits a conditional stale-read / same-identity double-release chain, not allocator-bin conclusions.

## Precision regressions

Negative cases lock:
- `merge(0,1)` -> no alias relation;
- unresolved distinct expressions -> no alias relation;
- different helper name -> cannot inherit UBW semantics;
- policy without realloc-move/free behavior -> alias fact only, no double-release promotion.

## Not claimed

No concrete realloc-move runtime fact, unsorted-bin placement, consolidation, changed-size second free, tcache/fastbin placement, poisoning, largebin or FSOP is claimed in Cycle-21.

## Next divergence

Prove the allocator state that makes the first realloc release and the second release land in distinct useful states. In parallel, start heapMage with explicit glibc-2.39/environment evidence.
