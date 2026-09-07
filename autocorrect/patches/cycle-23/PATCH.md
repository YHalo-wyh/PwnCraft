# Cycle-23 — SCTF 2026 / heapMage bounded adjacent metadata truth

Status: **ACCEPTED on branch; pending final main gate**

## Clean-room source truth

The official source defines a `0xc0` small allocation but `edit()` always performs `read(..., 0xf0)`.  A maximal edit therefore overflows exactly `0x30` bytes into the next chunk metadata.

The full span covers the next chunk's:

- `prev_size`
- `size`
- `fd`
- `bk`
- `fd_nextsize`
- `bk_nextsize`

The source also contains a guard for long edits: the masked next `size` at `+0xc8` must remain in `[0x20, 0x520]`, and the next `bk` at `+0xd8` must reference the tracked heap range.

The official exploit writeup explicitly discusses **glibc 2.39** behavior.

## Generic fix

Added `AdjacentChunkMetadataPolicy` + `derive_adjacent_chunk_metadata_overwrite()`.

The engine computes field coverage from reviewed relative geometry and returns the exact source constraints.  It does **not** infer a largebin attack or House of Rust from the technique name.

## Negative boundaries

- an edit of `<= 0xc0` is not an overflow;
- a length above the reviewed source maximum is rejected;
- bounded adjacent metadata corruption is not promoted to arbitrary-address write;
- allocator-version semantics require explicit reviewed evidence.

## Next

Model the exact glibc-2.39 smallbin/largebin transitions used by the official exploit to acquire a tcache-metadata chunk, then compose that state into a House-of-Rust capability.
