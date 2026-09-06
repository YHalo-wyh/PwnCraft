# Heap Correction Model

Corrections are typed commands, not scene overlays:

- `LayoutPatch`: presentation only; no replay.
- `HelperContractPatch`: re-lower all calls sharing the contract ID.
- `ObservedMemoryPatch`: write concrete/symbolic bytes into `PhysicalMemory` with `USER_OBSERVED` provenance.
- `StructuralViewPatch`: register a typed candidate view without inventing allocator membership.
- `AllocatorProfilePatch`: change an explicit allocator rule and replay from its checkpoint.

## Constraint status

- `VALID`: coherent under current physical and allocator rules.
- `REPRESENTABLE_CORRUPTION`: bytes can exist, but a later glibc check may abort.
- `INVALID`: cannot fit the field/range/address or violates a structural edit invariant; commit is rejected.
- `UNKNOWN`: evidence is insufficient; it is never coerced to zero.

The constraint modules cover range/width, chunk size/MINSIZE/alignment, structural `prev_size`, top bounds, doubly linked bin reciprocity and freelist alignment. `bin_location` is a computed read-only view. Safe-Linking uses `PROTECT_PTR(field_address, target)`, never heap base.

There is no Force Apply. An observed corrupt byte may be recorded as corrupt; a structural declaration with the same incoherence is rejected. Semantic undo/redo restores the exact sparse `PhysicalMemorySnapshot` in place and schedules replay from the first affected checkpoint.

`artifacts/correction_v012.json` contains 24 reproducible memory patch, validation, corruption and undo/redo cases.
