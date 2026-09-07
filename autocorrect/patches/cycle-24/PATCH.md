# Cycle-24 — R3CTF 2026 / Escape CET runtime control gate

Status: **ACCEPTED on branch; pending final main gate**

## Why this lane

PwnCraft already had stack/ROP UI and saved-RIP style capabilities, but that is not enough for a modern CET target.  The missing truth boundary was between:

`stack overwrite / saved RIP candidate`

and

`control flow that the reviewed runtime will actually permit`.

## Official runtime truth

The official deployment starts `tcet` under Intel SDE 10.8.0 with:

- `-cet 1`
- `-cet-endbr-exe 1`

The challenge therefore provides reviewed runtime evidence for CET enforcement rather than merely an ELF feature-note hint.

## Generic fix

Added `ControlFlowEnforcementPolicy` + `assess_saved_return_control_under_policy()` in `reviewed_allocator_control.py`.

The control promotion gate keeps these facts separate:

1. saved return-address overwrite;
2. shadow-stack synchronization evidence;
3. whether the candidate uses an indirect branch;
4. reviewed ENDBR-compatible target evidence under IBT.

With shadow stack enforced, saved RIP alone is blocked by `shadow_stack_return_mismatch`.  With reviewed IBT/ENDBR enforcement, an indirect target without compatible evidence is blocked separately.

## Negative boundaries

- saved RIP overwrite != executable ROP control;
- an IBT indirect target is not accepted just because its address is known;
- passing this mitigation gate still does not prove gadget semantics, CET bypass, arbitrary read, or exploit success;
- CET enforcement is taken from reviewed runtime evidence, not guessed solely from an ELF property.

## Next

Inspect the official handout binary and derive the first concrete vulnerability/control primitive that is compatible with the reviewed CET policy.  The next cycle must still keep vulnerability proof, mitigation bypass, and final exploit path as separate layers.
