# Cycle-30 — deterministic format-string target/write plan

Domain: `format_string`.

First divergence: prior support can split a value or delegate to
`fmtstr_payload`, but it does not own exact modulo padding, target writability,
and pointer-argument ordering as reviewed facts.

Patch: `reviewed_format_plan.py` emits an exact atom schedule only when target
address, desired value and target writability are all known. `%hhn/%hn/%n`
moduli are computed deterministically and unknown numeric inputs remain `None`.

The registered CCTF pwn3 train case proves symbolic `puts@GOT -> system` intent
and argument offset 7; its exact plan remains deferred until ELF/runtime values
are available. A numeric relocatable fixture tests the generic arithmetic
without inventing challenge addresses.
