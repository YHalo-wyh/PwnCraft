# Sunshine EXP AST / HeapViz 批量回放报告

- corpus: `/mnt/c/Users/WYH/Desktop/pwncraft/pwncraft_v0.5.0/artifacts/sunshine_ast_v012`
- EXP candidates: **0**
- syntax valid: **0/0**
- PARSE_ONLY: **0**
- MODEL_READY: **0**
- PARTIAL_REPLAY: **0**
- FULL_REPLAY: **0**
- SEMANTIC_VERIFIED: **0**
- STATIC_ELIGIBLE: **0**
- STATIC_PARTIAL: **0**
- RUNTIME_REQUIRED: **0**
- Raw Corpus Coverage: **0/0 = 0.00%**
- Static-Scope Coverage: **0/0 = 0.00%**

> `MODEL_READY` 表示 AST 已产生 allocator IR；`FULL_REPLAY` 仍不等于外部真值校准。
> 自定义 allocator、服务端隐式 malloc、竞态和动态分支必须配 behavior profile / pwndbg checkpoint，禁止猜测。

| status | eligibility | ops | chunks | aborted | reason | EXP | artifact |
|---|---|---:|---:|:---:|---|---|---|
