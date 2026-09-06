# v0.12 Offline Analyzer Architecture

## Data flow

```text
Python source
  -> ast.parse (never import/exec target code)
  -> HelperContractResolver
  -> CanonicalHeapOperation
  -> AbstractValue / PayloadIR
  -> legacy compatibility adapter
  -> GlibcHeapEngine
  -> PhysicalMemory
  -> typed views / HeapSnapshot
```

`CanonicalHeapOperation` owns `handle`, `menu_request`, `allocator_request`, `offset`, `length`, `payload`, `target`, `source_binding`, `contract_id` and confidence. `offset/length` are no longer hidden only in `meta`; the legacy adapter copies them into `meta` solely for the unchanged allocator boundary.

The value domain is `ConcreteInt / SymbolicInt / LengthExpr / PointerExpr / ConcreteBytes / SymbolicBytes / UnknownValue`. It evaluates only allow-listed AST nodes. Byte concatenation, repetition, slicing, `len`, `p8/p16/p32/p64`, `u32/u64`, `flat/fit`, `struct.pack`, `ljust/rjust` and `to_bytes` preserve exact or symbolic length.

## Determinism and offline boundary

- Helper names produce candidates, never proof.
- Runtime-only calls, sockets, unresolved iterables and unchosen dynamic branches remain `UNKNOWN`.
- Loop expansion is bounded by `max_loop_iterations` and `max_events`.
- Core analysis imports no HTTP client and makes no network request.
- `tests/test_heapviz_v012_offline.py` replaces socket/urllib/requests/httpx entry points with failing stubs while parsing, lowering, replaying and correcting.

## Compatibility

Existing `HeapOperation`, 60-case semantic benchmark, allocator templates and Pwndbg Runtime Truth Bridge remain supported. `legacy_from_canonical()` is the sole compatibility lowering point; it does not change physical truth rules.
