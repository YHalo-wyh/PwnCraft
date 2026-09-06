# v0.9.3 Validation

## 题目文件核对

用户给出的两个路径名存在偏差，实际可读路径为：

```text
C:\Users\WYH\Desktop\霄元杯\16：00\pwn_work
C:\Users\WYH\Desktop\霄元杯\pwn\exp.py
C:\Users\WYH\Desktop\霄元杯\pwn\pwn_wp.md
```

`pwn_work/httpd` 是 `ELF64 AArch64 PIE stripped`，与 EXP/WP 的 Magic Numbers 题不是同一个二进制。与 EXP/WP 实际匹配的附件为：

```text
C:\Users\WYH\Desktop\霄元杯\race\questions\PWN\e5e9af35b74948d7b4d47107f4f57dad\pwn
ELF32 i386 PIE, with debug_info, not stripped
```

## 精确静态结果

`exp.py` 的可证明链路是：

```text
bytes.fromhex(shellcode)
  -> SC.ljust(0x280, b'\x90')
  -> 4 * io.sendlineafter(MAGIC, b'0')
  -> io.sendafter(..., payload)
  -> io.interactive()
```

该题没有 heap helper 或 allocator 操作。权威静态结果：

```text
heap operations = 0
snapshots       = 1 (initial only)
chunks          = 0
handles         = 0
tcache/fastbin/unsorted/smallbin/largebin = empty
```

因此“精确堆模型”就是空模型。根据 `payload`、shellcode bytes 或 WP 注释画 chunk 都会构成 false positive。

详细机器可读证据：

```text
artifacts/case_audit/xiaoyuan_magic_numbers_v093/analyzer_result.json
SHA256 dc004cfb07021334ef58aa666d3001f33ec4c68be11522aaa9f34c5ccadd35d3
```

## UI 默认布局

- 外层 EXP/visual：`500/1000`
- 内层 Physical Heap/Bin Show：`700/300`
- 地址轴：`136px`
- Physical Heap 基准宽：`620 scene px`
- auto-fit floor：Heap `0.72`，Bin/Show `0.58`
- 布局持久化 schema：`9`

UI 回归会在 1500px 参考窗口同时校验：左栏大于 400px、中栏宽于右栏、Heap 和 Bin/Show 的 scene 默认 fit 在各自 viewport 内。

```text
artifacts/ui_audit/v0.9.3/three_column_fit.png
1603 x 900
SHA256 fad95f9ac0f17976280b87c22d87d3830ce31612e45ada958af41a646cbfebe7
```

## 回归与静态检查

```text
QT_QPA_PLATFORM=offscreen python -m pytest -q
168 passed in 12.44s

python -m ruff check pwncraft tests
All checks passed!

python -m compileall -q pwncraft tests
exit 0
```
