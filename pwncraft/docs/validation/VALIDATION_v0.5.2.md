# pwncraft v0.5.2 验证记录

## 自动化回归

Windows PyQt5 环境执行：

```bat
set QT_QPA_PLATFORM=offscreen
python -m unittest discover -s tests -v
```

结果：`Ran 63 tests ... OK`。

## 覆盖重点

- 5 类 alloc 参数形态、多行/关键字/默认参数、方法/别名/wrapper、静态 star 参数。
- range/enumerate/容器 append/容器索引/列表推导式/循环环境绑定。
- 未知分支共同前缀、路径选择、动态循环 unresolved 停止边界、语法错误保留旧快照、展开与事件上限。
- show/recv/u64/int.from_bytes 值流、fake chunk p64/flat、用户代码绝不执行。
- override 重绑与 stale、场景 v1/v2、helper profile 数据。
- known/zero/unknown 内存真实性、连续 NULL 居中误差不超过 2px。
- 七列时间线、100/115/130 主题和新版引导页验证。
