# HelperContract Resolver

`pwnbao/features/heapviz/contracts/` resolves callable syntax to an explicit contract:

```text
contract_id, function, receiver, operation, signature,
roles, effects, evidence, confidence, fingerprint, scope, status
```

Evidence priority is fixed:

1. user confirmed;
2. imported challenge profile;
3. inline `# pwnbao:` annotation;
4. structural helper-body proof;
5. wrapper propagation;
6. exact assignment/partial alias;
7. name candidate;
8. unknown.

Supported forms include reordered positional/keyword/default arguments, compact names, multiple helpers per semantic, methods, exact assignment aliases, simple `functools.partial`, wrappers with argument expressions and bounded wrapper-cycle detection. Ordinary `dict.update`, `set.remove` and `os.remove` are excluded.

The **Function Adapter / Auto Contract** page lists evidence and exposes operation plus index/size/offset/data argument dropdowns. Confirming once stores a challenge-scoped contract and re-lowers every matching call. The function AST fingerprint is checked on every load; a changed signature/body marks the stored rule `STALE` rather than applying it silently.

Persistence uses schema 4 and serializes full contracts, not only helper names. Scene import restores contracts before subsequent source analysis.

## Acceptance examples

- `addchunk(3, b'A', 0x80)` with signature `(idx, content, size)` -> `ALLOC(index=3,size=0x80,data=b'A')`.
- helper request `len(data)` with `b'A'*0x80` -> `0x80`.
- `b'A'*n+p64(x)` -> symbolic length `n+8`.
- `edit(0,0x18,b'B')` -> offset `0x18`, length `1` and a write to `chunk.user+0x18`.
