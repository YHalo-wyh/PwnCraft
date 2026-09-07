# Cycle-26 — deterministic format counted-write semantics

Status: **ACCEPTED candidate pending branch/main gates**

## First divergence

The old formatter treated `%n` as a generic write surface but did not separate argument position, C write width, or whether the preceding output count was statically knowable. That was too coarse and could be misread as an arbitrary-write claim.

## Generic fix

`fmt_semantics.py` now records:

- positional target argument index;
- `%hhn/%hn/%n/%ln/%lln` width under the reviewed amd64 SysV ABI;
- exact preceding count only when output length is deterministic;
- `value_modulo` only when both count and width are known.

A literal `%1$1001c%7$n` therefore yields argument 7, width 4, value 1001. A value-dependent prefix such as `%31$p...%6$n` retains argument 6/width 4 but leaves the write value unknown.

## Real-case truth

The registered CSAW contacts EXP uses `%31$p`, `%6$p/%11$p`, and a final `%6$n`; its preceding widths are assembled from runtime values. Cycle-26 therefore proves target position/width while explicitly refusing to invent the runtime write count.

## Negative boundaries

- `%n` presence is not called unrestricted arbitrary write;
- unresolved `*`, `%s`, `%p`, integer conversion output etc. poison exact-count knowledge;
- ABI-dependent `j/z/t` widths remain unknown.

Next: compose a proven format-write target address/value with writable-target evidence, separately from the formatting primitive.
