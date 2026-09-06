# pwn宝 v0.6.1 验证记录

## 自动化回归

Windows Python 3.10 + PyQt5 offscreen 环境执行：

```bat
set QT_QPA_PLATFORM=offscreen
python -m compileall -q pwnbao tests
python -m unittest discover -s tests -q
```

结果：

```text
COMPILE_OK
Ran 81 tests in 4.902s
OK
```

## v0.6.1 新增覆盖

- `AIProviderConfig` 手动模式、8K context、6000 input、2048 output 和 180 秒默认值。
- `PromptBudget` 可接受/超限路径，并证明超限请求不会发起 HTTP POST。
- Validator 对单次 40 条输入只接受前 32 个候选并产生诊断。
- 手动 AI 模式下 `_schedule_ai_analysis()` 不启动防抖计时器。
- Heap 右侧工具抽屉和画布的双向切换，包括时间线/AI 导航状态和关闭恢复。
- 原有 AST 语料、allocator、分支/校正、真实性内存、NULL 折叠、双链 bin、地址轴、UI 缩放和 LM Studio 假服务回归继续通过。

## UI 尺寸检查

- Offscreen 实例在 960×640、1180×760、1540×940、1707×1067 与 100%/115%/130% 三档显示比例下逐一触发响应式布局。
- 960px 紧凑布局默认收起 EXP 工具侧栏；1180px 与更宽布局恢复侧栏。顶部 EXP/堆可视化/工具栏/缩放/任务设置在 130% 下仍保持独立几何范围。
- 地址轴保持最低 11pt，已知字段换行后扩展行高，NULL 折叠行水平居中的既有误差回归仍为 2px。

## 本机模型状态

- 已确认硬件：i9-14900HX、32GB RAM、RTX 4060 Laptop 8GB。
- LM Studio 目录中的 `Qwen3.6-27B-Q4_K_M.gguf` 在验证时仍是 `.part` 下载文件；`mmproj-Qwen3.6-27B-BF16.gguf` 为 931,145,856 bytes。因主模型尚未完整下载，本轮不伪造“已在 LM Studio 成功加载”的结论。
- 下载完成后的最小实机复核：不加载 mmproj，8K context + Flash Attention，GPU offload 逐层提高并预留约 1GB 显存；启动 Local Server 后在 AI 页点击连接，检查 `/v1/models`，再手动点击“分析当前 EXP”验证 `/v1/chat/completions`。
