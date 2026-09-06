# pwncraft v0.6.4 验证记录

## 自动化测试

```text
QT_QPA_PLATFORM=offscreen python -m compileall -q pwncraft tests
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -q
Ran 83 tests
OK
```

## 窗口与布局验证

- EXP 模式为左侧工具栏、右侧编辑器、底部折叠日志。
- Heap 模式隐藏主侧栏和日志，HeapViz 内保持 42/58 的 EXP/画布布局。
- 时间线从底部展开；AI 校正从画布右侧展开，打开 AI 时自动收起底部抽屉。
- 已保存配置启动后的可见顶层控件只有一个 `MainWindow`。
- 单实例激活、隐藏画布标签和任务配置持久化修复保持有效。

## 功能回归

- 83 项测试覆盖 AST 变体、allocator、场景 schema、时间线、画布真实性、格式化字符串和本地 AI 协同。
