# Cycle-22 — SCTF 2026 / UBW allocator-state composition

Status: **ACCEPTED candidate pending final branch/main gate**

## First divergence

Cycle-21 stopped correctly at a conditional same-identity double release.  It deliberately could not explain why the two releases land in different allocator states.

## Reviewed truth

Official EXP + official writeup establish the state needed for the intended front-half route:

- first identity size class: `0xa0`;
- that tcache class is full before `merge(0,0)`;
- first release therefore bypasses the full cache and participates in the reviewed unsorted/consolidation path;
- reviewed adjacent free span changes the chunk header from `0xa0` to `0xf0`;
- the `0xf0` tcache has capacity after the EXP drains one entry;
- the stale second release uses the resized header and can place the same identity in that second cache class.

The realloc-move/free-old condition from Cycle-21 remains explicit.

## Generic fix

Added `ResizedDoubleReleasePolicy` + `derive_resized_double_release_bins()` in `reviewed_allocator_control.py`.

The engine requires:

1. an upstream conditional same-identity double-release fact;
2. reviewed allocator family/version;
3. reviewed first-cache fullness;
4. reviewed consolidation and exact resized header;
5. reviewed second-cache capacity.

It emits `same_identity_cross_bin_membership`, **not** tcache poisoning.

## Negative boundaries

- first cache not full -> no bin derivation;
- missing upstream alias double-release -> no derivation;
- cross-bin membership does not become arbitrary allocation/tcache poisoning.

## Next

Compose the official safe-linking freelist manipulation and prove the poisoned allocation target/returned identity.
