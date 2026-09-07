# Cycle-31 — SCTF 2026 heapMage / libc seed -> stdout leak

Domain: `leak` with reviewed glibc-2.39 allocator state.

The official exploit uses the Cycle-27 `heap+0x90` tcache-metadata allocation to
forge a 0x100 chunk at `heap+0x100`. With tcache[0x100] full, freeing that chunk
routes it to unsorted and fd/bk libc pointers overwrite entries[14]/entries[15].

Patch: static libc-pointer seeding, the 16-way low-nibble stdout candidate, and
runtime libc-base derivation are separate APIs. The exact base is emitted only
after an observed stdout-relative pointer satisfies the reviewed formula
`leak - (_IO_2_1_stdout_ + 0x84)`.

Boundary: no candidate is marked correct statically and Apple2 remains
downstream.
