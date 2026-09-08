# Cycle 38 — ELF-bound exact Format GOT plan

## First divergence

Cycle 30 deliberately stopped CCTF-style format-string planning at a symbolic
`puts@GOT -> system` relation because numeric target/value/writability were not
available.  Cycle 37 now supplies those facts from the exact local main ELF and
libc artifacts.

## Patch

`reviewed_format_elf_binding.py` composes four independently required facts:

1. exactly one relocation for the requested import symbol;
2. the relocation target is in a writable PT_LOAD region and outside
   PT_GNU_RELRO;
3. one observed runtime address of a defined libc symbol yields
   `libc_base = observed - symbol_offset`;
4. the desired libc symbol is resolved from the exact same libc artifact.

Only after those checks pass does the layer call the existing exact modulo
format-write planner.

The returned state records both artifact SHA256 digests, the relocation type and
artifact/runtime addresses, the observed base formula, the desired runtime
symbol address, and the nested exact write plan.

## Negative gates

Regression coverage keeps the result unknown when:

- GNU_RELRO covers the target relocation;
- the observed libc symbol is absent from the supplied artifact;
- either artifact snapshot is degraded/incomplete;
- a PIE main has no reviewed runtime load base;
- relocation identity is ambiguous.

## Capability boundary

`elf_bound_exact_format_got_rebind_plan` is still a write plan.  It does not
prove attacker bytes reach printf, that the planned `%n` atoms execute, that a
later call reaches the rewritten import, or that the desired libc function
achieves shell/flag behavior.
