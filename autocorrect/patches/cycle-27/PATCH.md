# Cycle-27 — SCTF 2026 / heapMage smallbin-to-tcache stash truth

Status: **ACCEPTED candidate pending branch/main gates**

Cycle-23 stopped at a bounded adjacent metadata overwrite. The official exploit then documents one glibc-2.39 smallbin allocation that returns V0 while stashing `V1,V2,V3,fake,p2,V4`; later cache pops are `V4,p2,fake`, where fake user is `heap+0x90` at `tcache->entries`.

Production adds a reviewed stash composition requiring the upstream bounded overwrite, exact reviewed traversal, sufficient tcache room and reviewed list integrity. It derives traversal order, LIFO pop order and the exact nth returned user pointer.

The promoted capability is only `reviewed_fake_user_allocation_acquired`. Missing room/integrity or a mismatched expected return blocks the claim. House-of-Rust/Apple2 names never trigger semantics.

Next: use the acquired metadata user to prove the later libc-pointer seeding/stdout leak chain.
