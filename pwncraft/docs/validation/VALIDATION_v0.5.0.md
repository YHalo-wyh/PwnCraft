# pwncraft v0.5.0 验证记录

## 已验证
- `python -m compileall -q pwncraft tests` 通过。
- `PYTHONPATH=. pytest -q tests/test_heapviz_core.py`：**28 passed**。
- `PYTHONPATH=. pytest -q tests/test_heapviz_gui.py -q`：**15 skipped**。

## 跳过项说明
当前容器环境没有安装 `PyQt5`，因此无法真实创建 GUI 窗口做运行时 smoke test；GUI 相关测试仍保持 skip，而不是伪装成通过。

## 本次重点确认
- UI 主题修改后，源码可正常编译。
- 新增“自定义 Chunk”教学层逻辑不会参与 allocator 计算。
- 快照展示改为“真实快照 + 可选手动画布覆盖”，不会影响核心 replay 结果。
- 现有核心 heapviz 回归未被破坏。
