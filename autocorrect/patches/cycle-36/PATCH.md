# Cycle-36 — SCTF 2026 heapMage / reviewed wide-data state

Domain: `io_file / heap`.

Cycle-35 proves only one runtime-bound tcache return at
`wide_data = libc_base + 0x204800`.  The official heapMage writeup then reuses
the same reviewed `malloc_100_at()` mechanism for
`wide_vtable = libc_base + 0x204900` and writes the separate wide-data object.

`build_fake_wide_data()` gives exact field geometry: `wide+0x18=0`,
`wide+0x20=1`, `wide+0x30=0`, and `wide+0xe0=wide_vtable`.

Patch: `reviewed_wide_data_state.py` requires two independently proven exact
allocation returns plus exact reviewed field writes.  A wrong second target,
missing allocation, wrong wide-vtable pointer, malformed/duplicate field write
or unreviewed field state stays unknown.

Boundary: this proves only `reviewed_wide_data_state_prepared`.  The wide-vtable
region's `__doallocate` slot is deliberately deferred because the target libc
`system` symbol is still symbolic in the inspectable evidence.  Fake FILE
binding, dispatch, command execution, shell and flag retrieval remain downstream.
