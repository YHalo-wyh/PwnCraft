# Allocator Truth Audit — v0.10

## 审计结论

`PhysicalMemory` 是唯一字节真值；任何 refresh/enrich/UI pass 都不得重写攻击者已修改的 metadata。逻辑身份与 arena head/cache 可以存在，但必须能检测与 memory 的分裂。

| allocator 行为 | v0.9.5 主要依据 | v0.10 决策依据 | cache 是否仍参与 | corruption 后结果 |
|---|---|---|---|---|
| chunksize | memory 优先、hint fallback | `chunk+SIZE_SZ` PhysicalMemory | hint 只在 unknown 时展示 | 影响 bin/merge/split |
| backward consolidation | freed lifecycle + adjacency | 当前 `size.PREV_INUSE`、`prev_size`、prev.size | lifecycle 仅一致性检查 | P=1 阻止；P=0 才解析 prev |
| forward consolidation | 相邻 freed state | chunk-after-next 的 P bit + next.size | bin membership 只作可达性检查 | footer/P bit 改变结果 |
| tcache duplicate | `chunk_id in list` | entry.key；命中后沿 memory.next traversal | head/count cache | key=0 可绕过 |
| tcache/fastbin next | list order | actual next field + actual safe-link field address | head/bucket cache | poisoned target 成为真实 head |
| top split | `_next_offset` cursor | PhysicalMemory top.size + checks | `_next_offset` 仅地址 | top overwrite 被下一次 malloc 消费 |
| top merge | 邻接与 cursor | old top.size + freed size | 地址 cache | 写回合并后的真实 size |
| unsorted/smallbin unlink | Python list transition | victim fd/bk + reciprocal links + virtual BinHead | bucket/order cache | corruption 触发正式 abort |
| largebin | list + conservative best fit | fd/bk unlink memory-driven；nextsize 有物理 view | size order仍为保守 cache | 普通链 corruption 可 abort；完整 attack 未实现 |
| overlap | ChunkState 同步 | 一份 PhysicalMemory、多 view | 无 byte cache | 所有 view 即时一致 |
| fake chunk | 变量名启发 | layout candidate -> allocator reference confirmed | evidence state | ROP 不再 confirmed |

## Invariants

1. allocator write 只改必要 spans。
2. `assert_cache_consistency()` 失败时不 repair memory。
3. `WriteImpact` 的 `[physical_start, physical_end)` 与 field/payload offset 可重放。
4. abort 后 strict replay 不再制造后续 allocator state。
5. runtime calibration 一律标记 `CALIBRATED`。

## 尚未闭合

- tcache TLS head/count 仍是抽象 arena cache，不是完整 libc TLS memory layout。
- largebin nextsize 排序和版本差异只覆盖 CTF 常见子集。
- mmap、多 arena、heap extension、所有 sysmalloc 分支未实现。
- corpus 中服务端隐式 malloc/custom protocol 没有 behavior profile 时保持 PARSE_ONLY/PARTIAL，不猜。
