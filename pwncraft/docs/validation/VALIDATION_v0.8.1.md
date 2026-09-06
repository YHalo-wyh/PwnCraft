# v0.8.1 验证记录

## 覆盖重点

- 固定 115% UI 密度，旧缩放设置迁移，不再创建缩放组合框或快捷键。
- HeapViz 八个工具页名完整显示，自适应多行排列，窄宽度下不用省略号代替功能名。
- AI 高置信度 no-op 候选仍会被本地私有 replay 监督器拒绝，并去重持久化为负反馈与 fixture。
- 监督器使用当前 helper/behavior profile，只过滤候选，不直接改写 EXP 或 allocator 状态。

## Windows 视觉验证

- `artifacts/ui_audit/heap_controls_v081_windows.png`：八个导航项两行完整显示，无文字省略或按钮重叠。
- `artifacts/ui_audit/heap_workspace_v081_windows.png`：左侧 EXP/语义工具与右侧 Heap/Bin 保持可用宽度。
- 渲染使用 Windows Qt、`Qt.WA_DontShowOnScreen` 和 `QWidget.render()`。

## Qwen Coder 实机验证

- LM Studio model ID：`qwen3-coder-30b-a3b-instruct`。
- 加载参数：4096 context、parallel 1、GPU offload 30%、TTL 3600s。
- 测试 case：`datasets/heap_ai/manifest.json` 中的 `local.traditional.solve`。
- 结果：57 个静态语义操作，0 个 raw/valid AI 候选，模型明确回复无需追加 allocator 事件；耗时 15781ms，完整 EXP 未截断。
- 产物：`artifacts/ai_eval_v081/local.traditional.solve.json`、`gap_report.json`、`aggressive_learning_report.json`。

## 回归命令

```powershell
set QT_QPA_PLATFORM=offscreen
python -m unittest discover -s tests -p "test_*.py" -v
python -m compileall -q pwncraft tests run_pwncraft.py build.py
```

## 结果

- unittest：150 项通过。
- compileall：通过。
- Windows Qt 完整工作区与工具导航截图：人工视觉核对通过。
- 当前 Windows Python 环境未安装 `ruff`，本轮以 compileall 和 unittest 作为静态/行为回归；未伪报 ruff 成功。
