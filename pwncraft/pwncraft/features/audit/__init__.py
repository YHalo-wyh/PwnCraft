"""EXP Live Auditor — deterministic kernel (VNext.3).

Semantic verification of a pwn EXP against the target's BinaryIR /
ChallengeBehaviorProfile / heap state. NOT a python linter: every rule
encodes pwn-specific semantics (leak packing, arch width, PIE assumptions,
heap lifecycle conflicts).

Design directives locked by the owner:
  * two layers — this module is layer 1 (local, deterministic, ms-level);
    AI reasoning is layer 2, invoked on demand with minimal context.
  * UNKNOWN ≠ FALSE: unconfirmed target behavior yields a Suggestion with
    confidence < 1, never an error.
  * diagnostics carry evidence and impact; quick fixes are suggestions the
    user applies — the auditor never mutates the EXP.
  * decompiler/assembly backends are interchangeable; this layer consumes
    ExploitIR + BehaviorFacts, not raw disassembly.
"""
from __future__ import annotations
