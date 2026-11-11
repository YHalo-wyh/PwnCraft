# Cycle-33 — SCTF 2026 UBW / reviewed stdout FILE path

Domain: `io_file / control-flow boundary`.

Cycle-29 stopped at one exact reviewed largebin side effect: the stdout pointer
variable receives chunk B's header address.  The official UBW EXP then builds B
as a fake FILE object, while the official writeup explicitly states that the
later `printf("blade: ...")` output triggers the IO path.

First divergence: PwnCraft had FILE layouts and source hints, but no generic
reviewed composition from an already-proven stream-pointer binding to a
reviewed FILE field state and an independently reviewed stdio trigger.

Patch: `reviewed_stdio_path.py` requires all of the following before promotion:

- exact upstream pointer write to the reviewed stream pointer;
- exact object/payload geometry;
- explicit reviewed FILE roles, including a non-empty write window and non-zero
  lock/wide-data/vtable structural pointers;
- an independently reviewed trigger that reaches the same stdout stream.

The production rule never recognizes `FSOP` or `House-of-*` names.  Missing or
wrong pointer bindings, missing FILE roles, an empty write window, or an
unreviewed trigger all remain unknown.

Boundary: this cycle proves only `reviewed_stdio_path_reachable`.  It does not
prove wide-data/vtable dispatch semantics, `setcontext`, stack pivot, ROP/ORW,
shell, flag retrieval, or runtime exploit success.  Those remain downstream.
