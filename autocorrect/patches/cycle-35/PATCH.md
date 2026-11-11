# Cycle-35 — SCTF 2026 heapMage / exact runtime-bound tcache target

Domain: `heap / allocator_control`.

Cycle-31 stops after separating a libc-origin pointer seed, a finite stdout
low16 candidate and a runtime-only libc-base derivation.  The next reviewed
boundary is one exact libc allocation target, not an unrestricted "arbitrary
malloc" capability.

The official heapMage writeup states that after the stdout leak the 0x100 tcache
still has a positive count.  Its `malloc_100_at()` helper rewrites metadata-user
offset `0x70` (entries[14]) with an exact address, then performs the reviewed
`malloc(0xf0)` path.  The first target used by the official Apple2 preparation
is `wide_data = libc_base + 0x204800`.

Patch: `reviewed_tcache_metadata_target.py` requires both independent upstream
facts: Cycle-27's acquired tcache entries user and Cycle-31's actually observed
libc base.  It then checks exact entries[14] geometry, target = observed base +
reviewed offset, 0x10 target alignment, positive reviewed tcache count, the
reviewed entry write and reviewed size-class allocation semantics.

The emitted capability is only `reviewed_exact_tcache_allocation_target` for
that one runtime-bound target.  A low16 libc candidate, wrong metadata user,
wrong target relation, unaligned target or unreviewed count/allocation state
stays unknown.

Boundary: this cycle stops at the returned `wide_data` user pointer.  The later
wide-vtable target, fake FILE target, field writes, system dispatch and command
execution remain downstream.
