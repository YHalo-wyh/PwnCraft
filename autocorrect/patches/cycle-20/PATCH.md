# Cycle-20 · SCTF 2026 CHAOS;HEAD · corrupted bounds -> adjacent control

Status: **ACCEPTED candidate pending final branch/main gate** · 2026-09-07

## First divergence

The official case already establishes a dangling transaction reference that corrupts `SnapshotPage.len/capacity`, but PwnCraft lacked a generic way to compose a reviewed corrupted bound with reviewed adjacent-object geometry and derive exactly which neighboring field becomes readable/writable.

## Locked truth

Reviewed official facts:
- `SnapshotPage` size `0x800`, data starts at `+0x20`, normal capacity `0x7e0`;
- `DUMP` caps output at `0x1000` and calls `route->sink(page+0x20,size,route->file)`;
- official EXP reads `route.sink` from leak offset `0x830` and sends a `0x900` payload;
- `CLEAR` resets len/hash but preserves the corrupted capacity;
- the post-CLEAR payload overwrites `route.sink`, and the next DUMP performs the indirect call.

## Generic patch

`AdjacentObjectPolicy` + `derive_adjacent_object_chain()` perform deterministic span composition only. The production rule knows no `SnapshotPage`, `route`, SCTF name, or setcontext address.

It can derive:
- adjacent-object read reaches a reviewed field;
- corrupted capacity survives a reset operation;
- an accepted write span reaches the adjacent function-pointer field;
- a reviewed indirect call through that field becomes a static indirect-control-transfer relation.

## Precision regressions

Negative cases lock:
- reset repairs capacity -> no post-reset overwrite;
- accepted payload is too short -> no field overwrite;
- dump cap is too short -> no adjacent read claim.

## Not claimed

The dangling-reference root cause is still reviewed upstream truth, not automatically recovered from the binary. This cycle does not prove setcontext/ROP correctness, shell, or flag acquisition.

## Next divergence

Automate the transaction dangling-reference root cause from decompiler/binary facts later; meanwhile continue breadth with UBW and heapMage.
