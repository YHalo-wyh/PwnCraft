# Cycle 42 — CCTF pwn3 exact artifact-bound format plan

## First divergence

Cycle 30 intentionally stopped at a symbolic `puts@GOT -> system` intent because the exact main ELF/libc numeric facts had not entered the deterministic evidence layer. Cycle 38 then added the generic ELF-bound format planner, but its regression used synthetic CCTF-like values rather than the registered train artifact itself.

The remaining gap was challenge instantiation, not planner arithmetic.

## Pinned evidence

The registered CTF-Wiki corpus was pinned to commit `047935a8cd4020c78bf84c36e761cf6d19421e1f`. A one-time CI evidence collection on the exact corpus files established:

- `pwn3` SHA256 `4fddf60b4838794808fe865579aa6416f53ba40c030dde3854ee63957930bfa5`;
- paired `libc.so` SHA256 `e57fa6bf382a5c8d20895a434317f3f6767e7f5b6485bc47970bd9a1cc5d471d`;
- `pwn3`: ELF32, little-endian, `EXEC`, Intel 80386;
- one `R_386_JUMP_SLOT` relocation for `puts@GLIBC_2.0` at `0x0804a028`;
- writable LOAD covers that address;
- GNU_RELRO spans `0x08049f08..0x0804a000`, therefore the exact puts relocation lies outside RELRO;
- paired libc `puts@@GLIBC_2.0 = 0x5fca0`;
- paired libc `system@@GLIBC_2.0 = 0x3ada0`.

The temporary networked collection step was removed immediately after locking these facts. The normal training gate remains free of challenge-download dependencies.

## Patch

No new arithmetic engine was added. Cycle 42 deliberately reuses `derive_elf_bound_format_got_rebind_plan()` from Cycle 38 and gives it exact CCTF artifact evidence.

With a runtime-observed `puts_addr` from the corpus EXP:

```text
libc_base  = puts_addr - 0x5fca0
system     = libc_base + 0x3ada0
target     = 0x0804a028
fmt arg    = 7
write bits = 32
atom bits  = 16
```

Only after relocation identity, writability and runtime symbol binding all pass does the existing exact modulo planner emit `elf_bound_exact_format_got_rebind_plan`.

## Hard boundary

This cycle still does **not** prove:

- attacker-controlled `put()` content reaches the vulnerable formatting sink;
- the generated payload is placed with the exact pointer/argument layout expected by the target process;
- the GOT write executes successfully at runtime;
- a later `get`/`dir` action invokes the rebound `puts` entry;
- `system('/bin/sh')`, shell, or flag retrieval.

Those are transport/reachability/trigger layers for the next format-string cycle.
