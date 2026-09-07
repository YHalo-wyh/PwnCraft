# Cycle-28 — R3CTF 2026 / blinky PAC speculative timing oracle

Status: **ACCEPTED candidate pending branch/main gates**

## Lane decision

Escape CET remains valuable, but the current connector exposes its official runtime/binary artifact metadata without inspectable instruction/decompiler truth. Moving beyond Cycle-24 would therefore require community writeup conclusions. The deterministic curriculum does not lower its evidence bar for that.

R3CTF `blinky` instead has official reviewed material describing the PAC gate, full RTL handout, reference solver behavior and fixed addresses, so this cycle uses it for the modern control-flow lane.

## Reviewed truth

Official material fixes:

- MIPS64r6 user->kernel indirect PAC protection for `[0x2000,0x100000)`;
- 8-bit tag in bits 63:56;
- probe address `0x1000` and target `0x2030`;
- under the reviewed speculative gadget, a good guess loads the probe while a bad guess is `NO_LOAD` and does not commit a PAC fault;
- reload timing distinguishes hit/miss;
- 8 bits imply 256 candidates in the fresh-run search space.

## Generic fix

A policy-gated PAC speculative oracle requires all asymmetric cache/fault/timing properties. Only then does PwnCraft emit `pac_tag_recoverable_via_reviewed_timing_oracle`; it does not invent the tag value before measurements.

## Negative boundaries

A committed bad-tag fault, no cache asymmetry, non-distinguishable timing, or target outside the reviewed protected region blocks the oracle.

Next: add runtime measurement evidence and separate tag recovery from authenticated target transfer.
