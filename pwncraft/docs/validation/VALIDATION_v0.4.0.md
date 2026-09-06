# pwncraft v0.4.0 验证记录

## 已执行

- `python -m pytest -q`
  - 28 passed
  - 15 skipped
- `python -m unittest -q tests.test_heapviz_core`
  - 28 tests OK
- Python AST 全项目静态解析：0 errors
- `python -m compileall -q pwncraft tests run_pwncraft.py build.py`：通过
- 严格模式 smoke：glibc 2.35 普通 tcache double free -> allocator aborted
- 兼容性 smoke：glibc 2.35 / House of Force -> unsupported

## GUI 验证说明

`tests/test_heapviz_gui.py` 的 15 个测试在当前打包容器中被跳过，因为该容器没有 PyQt5；尝试安装 PyQt5 时当前环境没有可用发行包/网络源。因此这里不冒充 GUI 自动化已经跑过。

项目依赖仍为 `PyQt5>=5.15.0`。在 Windows 开发机安装 `requirements.txt` 后，可执行：

```bat
set QT_QPA_PLATFORM=offscreen
python -m unittest -v tests.test_heapviz_gui
```

## 设计边界

HeapViz v0.4.0 的 allocator 是面向 CTF 辅助的保守语义模型，不是 glibc `malloc.c` 的逐指令复刻。严格模式用于避免“利用意图直接篡改事实”；Pwndbg 校准用于发现模拟与真实运行状态开始偏离的位置。
