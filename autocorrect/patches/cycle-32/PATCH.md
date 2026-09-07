# Cycle-32 — Binary Semantic Provider contract

Domain: `binary_semantics / control_flow infrastructure`.

PwnCraft already has `ida_bridge` transports and BinaryIR, but modern binary-only
cases need a strict evidence boundary between IDA output and exploit reasoning.

Patch: `core/binary_semantic_provider.py` defines an offline JSON snapshot
contract. Every semantic record must carry an exact function address, exact
instruction/decompiler address, backend and provenance. Unsupported kinds,
duplicate evidence IDs, malformed addresses and name-only pseudo-evidence are
rejected. Records can be projected into BinaryIR-compatible evidence without
re-parsing machine code.

This is the provider foundation for the deferred Escape CET lane. It does not
claim that Escape CET's vulnerability/control primitive is solved yet.
