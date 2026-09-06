# pwn宝 v0.6.2 验证记录

## 自动化回归

```bat
set QT_QPA_PLATFORM=offscreen
python -m compileall -q pwnbao tests
python -m unittest discover -s tests -q
```

结果：

```text
COMPILE_OK
Ran 83 tests in 7.623s
OK
```

## 新增验证

- 第一个 `SingleInstanceController` 成功获取锁并监听；第二个同 key 实例不能再成为 primary，只发送激活消息。
- 清除已保存任务后构造 `MainWindow`，断言不调用 `TaskProfileDialog.exec_()`，并直接显示第三个内置任务页；启动后可见 top-level widget 严格只有主窗口。
- 运行记录 Dock 默认隐藏，展开后仍不是独立 Window；任务保存后返回 EXP 并持久化自定义 IO 变量。
- 960/1180px 响应式断点、130% 显示比例、Heap 工具抽屉、AI 手动调用、AST/allocator 和真实性画布回归继续通过。
