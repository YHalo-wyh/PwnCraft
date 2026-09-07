# Cycle-34 — SCTF 2026 UBW / reviewed wide-vtable dispatch target

Domain: `io_file / control_flow`.

Cycle-33 stops after proving that the largebin-rebound stdout pointer addresses a
reviewed fake FILE state and that the later `blade` printf reaches the stdout
stdio path.  The next deterministic boundary is not "FSOP success"; it is the
exact target selected by the reviewed wide-vtable dispatch.

The official UBW EXP writes `FILE+0xa0 = widep`, `FILE+0xd8 = libc+wfile`, then
builds the separate wide region with `widep+0xe0 = widep+0x100` and
`widep+0x168 = libc+setcontext`.  The same-event official Apple2 implementation
independently records the reviewed glibc geometry `OFF_WIDE_VTABLE=0xe0` and
`OFF_JUMP_DOALLOCATE=0x68`.  Therefore the reviewed dispatch slot is exactly
`widep+0x100+0x68 = widep+0x168`, which binds the slot to the official EXP's
`setcontext` target.

Patch: `reviewed_wide_dispatch.py` composes only exact upstream FILE bindings,
explicit reviewed slot geometry and exact address/value writes.  Wrong FILE
bindings, wrong wide-vtable pointer, wrong slot value, duplicate/malformed writes
or unreviewed semantics stay unknown.  Technique names are unused.

Boundary: this cycle proves `reviewed_stdio_dispatch_target_reachable`, not a
valid setcontext frame.  The exact target-libc instructions still need review
before PwnCraft may infer restored RSP/RIP, a stack pivot, ROP/ORW execution,
shell or flag retrieval.
