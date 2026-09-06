# pwncraft v0.6.0 验证记录

## 自动化回归

Windows PyQt5 + offscreen 环境执行：

```bat
set QT_QPA_PLATFORM=offscreen
python -m compileall -q pwncraft tests
python -m unittest discover -s tests -q
```

结果：`Ran 75 tests ... OK`。

## 新增覆盖

- 本地假 LM Studio HTTP 服务：`/models`、`/chat/completions`、Bearer token、结构化输出与 HTTP 400 JSON 回退。
- source hash、非法源码范围、未知 action/字段、虚假 observed/zero 内存事实的拒绝。
- urllib 超时错误、协调器 5/15/60 秒离线退避和手工连接后的恢复。
- generation 只接受最新响应；相同请求命中缓存，静态 IR 改变会形成不同缓存键。
- 已缓存候选在收到负反馈后仍会被过滤，不会重复弹出。
- SQLite feedback/rule/cache、规则启停、相似正负例检索和 JSONL 导出。
- 知识库路径损坏/不可写时退化为当前进程临时库，静态 AST/allocator 仍可正常启动。
- 精确 learned rule 可扩展 AST 分析；同函数/同参数数量但 AST 调用形态不同不会交叉套用，乱序关键字仍按 helper 参数角色绑定。
- 场景 v1 读取与 v3 AI review、规则、指令、禁用列表和内存标注 round-trip。
- AI 抽屉打开后底部抽屉自动收起，静态时间线由确认后的场景规则增强。

## UI 检查

- 1540×940 和 1180×760 下检查主编辑页、HeapViz 单行工具栏、42/58 工作区、底部抽屉与右侧 AI 抽屉。
- AI 抽屉在最小宽度打开时，EXP 编辑列保持可用，地址轴缩为紧凑模式，画布仍可滚动/缩放。
- 原有 100%/115%/130% 主题、引导页、Heap 卡片、NULL 折叠居中、双链 bin 和 EXP/时间线同步回归继续通过。
