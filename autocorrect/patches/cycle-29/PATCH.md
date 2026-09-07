# Cycle-29 — SCTF 2026 UBW / reviewed largebin pointer write

Domain: `heap / memory_write`.

Upstream truth is Cycle-25's controlled return at `a+0x10`. The official EXP
then writes the two largebin nextsize fields exposed by that returned region:
`A.fd_nextsize=A` and `A.bk_nextsize=stdout_ptr-0x20`. The official writeup
states that inserting the smaller largebin chunk B overwrites the stdout pointer
variable with B's chunk-header address.

Patch: `reviewed_largebin.py` composes only exact reviewed geometry and rejects
wrong target bias, wrong returned address, unreviewed insertion semantics or a
non-reviewed writable target.

Boundary: this cycle stops at the 8-byte stdout pointer write. FILE layout,
stdio trigger reachability and FSOP execution remain downstream.
