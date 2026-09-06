# pwncraft v0.6.5 验证记录

## 自动化测试

```text
QT_QPA_PLATFORM=offscreen python -m compileall -q pwncraft tests
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -q
Ran 83 tests
OK
```

## v0.5 布局验证

- 主工作区为侧栏、EXP/Heap 原生页签和下方日志。
- HeapViz 默认约 500/920，左侧同时保留 EXP 与语义操作，右侧保持主要画布宽度。
- 语义操作默认可见，不需要连接或启用 LM Studio。
- AI 是控制区中的独立辅助页签；退出 AI 后返回语义操作。
- 已保存配置启动时只有一个顶层主窗口。

## 功能回归

- AST、allocator、场景、时间线、画布、格式化字符串、AI provider 和规则学习测试均保持通过。
