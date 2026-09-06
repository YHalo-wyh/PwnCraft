# pwncraft v0.6.3 验证记录

## 自动化测试

```text
QT_QPA_PLATFORM=offscreen python -m compileall -q pwncraft tests
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -q
Ran 83 tests
OK
```

## 布局与窗口

- 工作区固定为 EXP 和堆可视化两个页面。
- 已保存任务配置时，启动后可见的顶层控件只有主窗口。
- HeapViz 的步骤、元信息、焦点、warning 和 override 标签均由画布容器持有，并保持隐藏，不再形成顶层小窗。
- 重复启动由 `QLockFile + QLocalServer` 拦截并唤起已有实例。
- 切换到堆可视化后，组件库和底部状态隐藏；切回 EXP 后按用户偏好恢复。

## 回归范围

- AST 变体识别、严格 allocator、MemoryRegion 真实性、时间线校正、Heap/Bin 绘制和 LM Studio 手动分析保持原有测试通过。
