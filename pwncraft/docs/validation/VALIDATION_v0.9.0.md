# v0.9.0 Validation

## Core / GUI regression

Windows Python 3.10 + PyQt5 offscreen：

```bat
set QT_QPA_PLATFORM=offscreen
D:\python310\python.exe -m unittest discover -s tests -v
```

结果：`161 tests / OK`。覆盖原有 AST、AI 候选监督、allocator、模板、scene、v0.5 工作区、单实例、Windows DPI 与新增 physical-memory tests。

Linux core runner 也完成全量 discover；当前环境没有 PyQt5 的 32 项 GUI 用例按设计 skip，其余全部通过。

## Ground-truth semantic benchmark

```bat
python -m pwncraft.tools.heap_semantic_benchmark
```

数据集：`datasets/semantic_benchmark/v0.9.json`

| Metric | Result |
|---|---:|
| Operation Precision | 100% |
| Operation Recall | 100% |
| Operation F1 | 100% |
| Argument Accuracy | 100% |
| Payload Span Accuracy | 100% |
| Write Range Accuracy | 100% |
| Overwrite Field Accuracy | 100% |
| Allocator Checkpoint Accuracy | 100% |
| Bin Membership Accuracy | 100% |
| Whole Case Pass Rate | 8/8, 100% |

机器可读结果：`artifacts/semantic_benchmark/v090_report.json`。

八个 case 分别覆盖 normal malloc/free、跨 chunk overflow、off-by-one、无 safe-link tcache poison、safe-linking stored/decoded、overlap、ROP 非 fake chunk、flat dictionary sparse offsets。这只是第一版公开 ground truth，不代表所有真实 CTF heap EXP 已达到 100%。

## 关键验收

输入：

```python
add(0x20, b'A')
add(0x20, b'B')
payload = b'A' * 0x28 + p64(0x51)
edit(0, payload)
```

实测：

- write destination `heap_base+0x2a0`，length `0x30`；
- payload `[0x00:0x20] -> A.user`；
- payload `[0x20:0x28] -> B.prev_size = 0x4141414141414141`；
- payload `[0x28:0x30] -> B.size: 0x31 -> 0x51`；
- `B.original_chunk_size=0x30`，current `B.chunk_size=0x50`；
- top 仍是 allocator 的物理 `heap_base+0x2f0`，不会被 B 被破坏后的 view end 错当成 top。

tcache poison 验收确认 engine 不再具有 `_pending_target_by_size`；外部 target 先成为 bin head，下一次 malloc 再消费。

可重放的文字证据：`artifacts/semantic_benchmark/acceptance_overflow_v090.txt`。

## Performance

在当前 WSL Python 3.12 上用 1024 个连续 alloc event 重放并保存每一步 snapshot：约 `11.9s`，最终 2049 个 sparse spans。实现没有 per-byte Python object；地址、span 和 enriched chunk view 使用索引/缓存。GUI analyzer 的总事件上限仍为 1024，避免无界展开。

## UI audit

- `artifacts/ui_audit/heap_physical_overwrite_v090_windows.png`
- `artifacts/ui_audit/canvas_physical_overwrite_v090_windows.png`
- `artifacts/ui_audit/overwrite_inspector_v090_windows.png`

截图验证低地址在上、top 使用 allocator 明确地址、A.user/B.prev_size/B.size 高亮、完整 payload mapping 与 before/after 可读。
