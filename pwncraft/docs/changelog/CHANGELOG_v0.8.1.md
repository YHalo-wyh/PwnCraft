# v0.8.1 - Full Text Controls + Local AI Supervisor

## UI 可读性

- 全局固定为一档 115% 逻辑密度，移除 100%/115%/130% 选择器和缩放快捷键。
- `build_stylesheet(scale)` 保留参数以兼容旧调用，但统一使用 `FIXED_UI_SCALE = 1.15`，避免 Windows DPI 与应用缩放叠加。
- HeapViz 底部八个工具页改为自适应多行文字导航，完整显示“语义操作 / 自定义 Chunk / 函数适配 / Pwndbg 校准 / 同步时间线 / Bin 文本 / 当前步骤细节 / AI 校正”。
- 导航按实际宽度自动换行，不再用 `QTabBar` 的省略文字；低频页仍在同一工作区内切换，不弹出多余窗口。
- HeapViz 默认左/右 splitter 调整为更适合可编辑 EXP 和堆画布的比例，旧布局设置会自动迁移。

## 本地 AI 监督

- 新增 GUI 候选私有重放监督：LM Studio 返回的每个候选都会使用当前 allocator、helper profile、behavior profile、分支选择、人工 override 和 Pwndbg 事实再次 replay。
- stale anchor、no-op、丢失事实、无效内存标注或引入新 allocator error 的候选会被自动隔离，不会进入“应用”列表。
- 监督器自动隔离的候选会去重写入负反馈和 regression fixture，后续 Qwen 提示可检索该反例。
- 监督器只有“拒绝候选”权限，不会私自修改 EXP、时间线、chunk 或 bin 事实。
- `StrictProposalReplayer` 现在接受当前 `HeapApiProfile` 和 `ChallengeBehaviorProfile`，预览与 GUI 当前题目语义保持一致。

## 实机验证

- 已通过 LM Studio 精确加载 `qwen3-coder-30b-a3b-instruct`：4096 context、parallel 1、GPU offload 30%、TTL 1h。
- 在 `local.traditional.solve` 完整 EXP 上实际调用耗时约 15.8 秒；模型判定静态 57 个操作已足够，返回 0 个多余候选，没有污染时间线。
