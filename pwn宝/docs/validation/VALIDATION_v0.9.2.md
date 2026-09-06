# v0.9.2 Validation

## 环境

- Windows Python 3.11.15
- PyQt5 offscreen platform
- 工作目录：`C:\Users\WYH\Desktop\pwn宝\pwn宝_v0.5.0`

## 自动回归

```text
QT_QPA_PLATFORM=offscreen python -m pytest -q
166 passed in 23.31s

python -m ruff check pwnbao tests
All checks passed!

python -m compileall -q pwnbao tests
exit 0
```

## 布局语义校验

`tests/test_heapviz_gui.py::test_loop_show_and_heap_leak_expression_become_value_flow` 现在同时校验：

1. `HeapPanel.visual_splitter` 包含物理堆与 Bin/Show 两个右侧子区域；
2. `show / value flow` 不存在于 `heap_canvas.scene`；
3. `show / value flow` 与 `tcache` 同时存在于 `bin_show_canvas.scene`；
4. 两个 scene 使用同一 step 的 `HeapSnapshot`。

## UI audit

- 可重放脚本：`artifacts/ui_audit/v0.9.2/capture_bin_show.py`
- 截图：`artifacts/ui_audit/v0.9.2/bin_show_split.png`
- 尺寸：`1603 x 920`
- SHA256：`e8a20f1a196bdc4492477e05727499eeda80778a6347c101f8bffdc458849bc9`

截图用例包含两个 allocated chunk、tcache free、`show()` 读取和 heap 派生值，用于同时观察中间物理堆区与右侧 Bin/Show 区。
