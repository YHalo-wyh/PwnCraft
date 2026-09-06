# v0.9.4 Validation

## 目标

画布内任何 allocator/chunk/bin/show 证据不允许因固定 cell 宽度被替换为 `…` 或 `...`。

## 实现校验

- `HeapAddressRail._draw_label` 不再调用 `elidedText`。
- `HeapCanvas._cell_value` 不再调用 `elidedText`。
- 短栏会逐级缩小字号到 7pt，仍不足时保留完整文本。
- `copy-overlapped` role 放到 chunk header 第二行，不再夹在 chunk ID 与 `idx/size` 之间。
- Show/value-flow 的 expression/value 使用容器内换行，长 symbolic value 不会把右侧 scene 横向撑大。

## 真实 snapshot 回归

`test_canvas_never_elides_copy_overlap_role` 构造：

```text
alloc A idx=0
alloc B idx=11
alloc C idx=12
copy B -> A length=0x80
```

校验最终 scene：

```text
copy-overlapped count >= 2
idx=11 is visible
no Unicode ellipsis
no ASCII truncation suffix
```

## 全量验证

```text
QT_QPA_PLATFORM=offscreen python -m pytest -q
169 passed in 18.37s

python -m ruff check pwncraft tests
All checks passed!

python -m compileall -q pwncraft tests
exit 0
```
