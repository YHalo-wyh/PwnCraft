# Cycle-25 — SCTF 2026 / UBW safe-linked freelist return

Status: **ACCEPTED candidate pending branch/main gates**

Cycle-22 proved same-identity cross-bin membership but deliberately stopped before poisoning. The official EXP now supplies the next exact relation: it writes `(a + 0x10) ^ (p0 >> 12)` and later asserts the controlled cache allocation returns `a + 0x10`.

Production adds a policy-gated safe-link decoder. It requires upstream cross-bin state, reviewed safe-linking parameters, alignment, cache-pop depth and an exact encoding match. The only promoted capability is `controlled_tcache_allocation_target` for that reviewed return.

Negative boundaries: wrong encoding, missing upstream state, misalignment or insufficient pop depth all remain unknown. This is not unrestricted arbitrary allocation and does not prove largebin/FSOP.

Next: compose the returned chunk with the reviewed largebin metadata write target.
