# Cycle 39 — Artifact-anchored runtime libc symbols

## First divergence

After Cycle 37, symbol offsets can be read from an exact libc artifact.  After
Cycle 31, heapMage can also have a runtime libc base derived from a stdout leak.
Those two facts still must not be combined blindly: a base derived with libc A's
stdout offset cannot be reused with libc B's symbol table.

## Patch

`reviewed_libc_symbols.py` introduces an explicit base anchor and role-specific
symbol requests.

Before resolving any requested symbol, the layer requires:

1. an observed-runtime libc base capability;
2. the upstream base-formula fact;
3. an anchor symbol from the exact supplied libc artifact;
4. equality between that artifact symbol's offset and the offset recorded in the
   upstream base formula.

Only then can requested symbols be resolved as runtime addresses.  Each request
can independently require an executable mapping or a writable/non-RELRO mapping.
This fits different roles without deriving semantics from names: e.g. a dispatch
function needs executable bytes while a mutable libc object needs writable bytes.

The emitted binding preserves the libc artifact SHA256, symbol offset, runtime
base, runtime address and the property gates applied to each role.

## Negative gates

The result stays unknown for:

- a base formula anchored to a different libc build;
- missing or undefined symbols;
- an executable role whose symbol lies outside executable PT_LOAD;
- a writable role covered by GNU_RELRO or outside writable PT_LOAD;
- degraded artifact snapshots.

## Capability boundary

`reviewed_runtime_libc_symbols_resolved` is address/provenance evidence only.  It
does not prove a dispatch reaches an executable symbol or that a writable object
can safely act as a fake FILE.
