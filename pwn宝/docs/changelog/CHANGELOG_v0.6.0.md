# pwn宝 v0.6.0

## 本地 AI 协同识别

- 新增 `features/ai` 分层：`OpenAICompatibleProvider`、`AIAnalysisCoordinator`、严格 `Validator` 和 SQLite `AIKnowledgeStore`。
- 默认对接 `http://127.0.0.1:1234/v1`，支持 `/models`、`/chat/completions`、Bearer token、JSON Schema 输出及普通 JSON 回退，不新增 SDK 依赖。
- 完整 EXP 在编辑停止 1.5 秒后异步分析；generation、source hash、请求缓存、串行线程池和 5/15/60 秒离线退避阻止旧结果覆盖新代码。
- AI 只产生 helper 映射、操作替换/插入/忽略、分支选择、值传播、内存标注和声明式规则候选，不直接修改 EXP 或 allocator 状态。
- 候选进入校正层前再次检查源码锚点、字段白名单、操作类型、内存边界/provenance，并在副本上执行严格 allocator replay。EXP 修改后的 stale 候选不可应用。
- AI 不允许生成 `observed` 内存事实或把未知内存标为 zero/NULL；确认后的内存标注只能是 `inferred/assumed`。
- AI 抽屉提供连接状态、模型、持续分析、本题指令、候选差异、严格预览、应用/学习/拒绝和撤销。双击候选可编辑 JSON，修改后重新走完整校验。

## 学习闭环

- “应用并学习”保存 accepted/modified 反馈；拒绝保存负样本，并同时过滤新响应和已有缓存中的同签名建议。
- helper 规则记录函数名、参数角色、关键字、参数签名以及去除字面量的 AST 调用形态；精确规则进入静态分析，模糊代码只参与相似样本检索。
- 全局规则可启用、停用、删除；反馈可导出 JSONL，供外部 LoRA/微调流程使用。
- 知识库默认位于 `%LOCALAPPDATA%\pwnbao\ai\knowledge.sqlite3`；只保存候选相关源码片段，API token 不写入 QSettings。
- Heap 场景升级为 schema v3，保存 AI review 引用、本题指令、场景规则、禁用规则和真实性内存标注，并继续读取 v1/v2。

## UI

- 启动引导改为紧凑双栏：左侧品牌/三步说明，右侧环境、程序/libc 路径、EXP 习惯和实时摘要，路径提供浏览按钮且只保留一个主操作。
- 侧栏收窄，运行记录默认折叠；HeapViz 顶部改为单行工具栏，低频场景/helper 操作收入菜单。
- HeapViz 默认约 42% EXP / 58% 画布；语义操作、时间线、函数适配、路线和 Pwndbg 放入底部折叠抽屉。
- AI 使用右侧可折叠抽屉，关闭时不占画布；打开时自动收起底部抽屉，并在 1180px 窗口重平衡 EXP、地址轴、画布和 AI 宽度。
- 全局版本更新为 v0.6.0。

## 稳定性与安全性

- OpenAI-compatible Base URL 仅允许 HTTP/HTTPS；非 loopback 地址明确提示会发送完整 EXP。
- 全局知识库损坏、锁定或不可写时自动退化为当前进程临时库，静态 AST/allocator 工作区仍可启动。
- QSettings 数值使用范围限制和损坏值回退；模型输出、场景、规则和缓存均作为不可信数据处理。
- AI 缓存键包含 allocator、静态 IR、分支/校正状态摘要、模型、规则和样本，不会因源码相同而复用错误的分支结果。
