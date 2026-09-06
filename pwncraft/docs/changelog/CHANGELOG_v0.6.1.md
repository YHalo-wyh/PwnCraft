# pwncraft v0.6.1

## Qwen3.6-27B 与本地 AI

- AI 默认调用节奏改为 `manual`。编辑 EXP、修改指令、切换模型或连接 LM Studio 均不再触发分析，只有“分析当前 EXP”会提交。
- `AIProviderConfig` 新增 `analysis_mode`、`context_budget_tokens`、`max_input_tokens`；默认为 8192 context、6000 input、2048 output、180 秒超时和 temperature 0.1。
- 新增 `PromptBudget`，在不引入 tokenizer 依赖的前提下对 JSON 提示做保守估算。超限请求在 HTTP 发送前终止，不静默截断 EXP。
- 静态 IR 移除重复源码字段，符号表只保留有界摘要，few-shot 检索数收紧为 4。JSON Schema 和 Validator 每次最多接收 32 个候选。
- 分析期间按钮改为“取消等待”。取消会使 generation 失效，旧响应不会进入候选区。
- 新增 AI 调用节奏设置迁移：旧 `ai/continuous` 和未版本化的模式一次性迁移为手动，场景 schema 仍为 v3。
- AI 设置页内置 Qwen3.6-27B-Q4_K_M 建议：8K context、Flash Attention、预留约 1GB 显存、纯文本不加载 mmproj。

## 全局 UI

- `QApplication` 创建前启用 High DPI Scaling、High DPI Pixmaps 和 PassThrough rounding，并统一 Fusion、Microsoft YaHei UI 与字体 hinting。
- 主窗口重构为全宽顶部栏、文字导航、蓝灰卡片和响应式 splitter。宽屏/常规/紧凑断点分别为 1400/1100/960px，紧凑模式收起 EXP 工具侧栏，不缩小正文字体。
- EXP 页的代码块、转换、Fmt、命令和 GDB 改为纵向导航 + `QStackedWidget`，长页使用滚动容器，不再堆叠横向页签。
- Fmt 改为“片段类型、动态字段、插入当前片段”单流程；转换列表选中不再自动覆盖系统剪贴板。
- 运行记录移入状态栏，按需打开可调整日志窗口，不再占用 EXP 编辑区高度。
- 引导页使用可响应双栏/单列滚动，任务环境、本题文件、EXP 习惯分卡片展示，路径带浏览按钮，仅保留一个主操作。
- 移除常驻装饰字符和图标，导航、状态和菜单均使用明确文字。
- 修复自定义 `io_name` 未进入 `{{IO_NAME}}` 代码块占位符的问题；EXP/Heap 切换分别保存布局，不再用硬编码宽度覆盖用户 splitter。

## HeapViz 工作区

- 删除固定 220–280px 底部抽屉。右侧使用 `QStackedWidget`：默认是 Heap/Bin 画布，打开工具后由完整右侧区域显示纵向导航和工具页。
- 新增 `HeapPanel.open_tool_page(page_id)` 与 `close_tool_drawer()`；时间线、操作、画布层、函数适配、路线、Pwndbg、Bin 文本、细节和 AI 共用统一导航。
- 工作区壳保留 `HeapPanel` 入口，纵向工具导航与 stacked workspace 拆到 `heap_tool_drawer.py`，AI 审阅面板、设置和候选编辑拆到 `ai_review.py`，避免继续向单个面板堆叠布局责任。
- chunk 地址插入改到右键菜单；双击使用上次的 header/user/fd/bk 类型，首次默认 user。
- 地址轴字号不低于 11pt；chunk 已知非空字段全量换行并扩展卡片高度，旧场景缺失内存证据时保持 unknown。
- 只有可证明的连续 NULL 范围使用居中折叠行；已知非 NULL 数据不使用省略号隐藏。快照焦点改为静态高亮，不再触发多轮全场景重绘。

## 版本

- 应用版本更新为 v0.6.1。
