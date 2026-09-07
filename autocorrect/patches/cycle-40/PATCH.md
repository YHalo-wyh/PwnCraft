# Cycle 40 — Reviewed wide-vtable dispatch binding

## First divergence

Cycle 36 proves a prepared wide-data object and its pointer to a separately
allocated wide-vtable region.  Cycle 39 can resolve an exact runtime executable
libc symbol from the exact libc artifact.  Those facts still do not prove that
the wide-vtable region actually contains that target at the dispatch slot used
by the reviewed Apple2 layout.

## Patch

`reviewed_wide_vtable_dispatch.py` composes:

1. a prepared wide-data state whose `wide+0xe0` points to the reviewed
   wide-vtable region;
2. an exact allocation return for that same wide-vtable address;
3. an artifact-anchored runtime libc symbol binding for the requested role;
4. one explicitly reviewed pointer-width slot write at the reviewed slot offset.

For the heapMage layout the official builder uses the wide-vtable `doallocate`
slot at `+0x68`; production code keeps the offset policy-driven rather than
matching the phrase House of Apple2.

## Negative gates

The result stays unknown for a mismatched wide-vtable region, missing exact
allocation identity, missing runtime symbol binding, wrong slot offset/value or
an unreviewed slot write.

## Capability boundary

`reviewed_wide_vtable_dispatch_target` proves only the slot's exact runtime
value.  It does not prove a fake FILE reaches the wide path, that stdio invokes
the slot, or that the target function executes successfully.
