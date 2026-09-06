# Qwen3.6-27B × pwn宝 traditional/solve.py 实测

## 结论

该模型能在本机运行并理解这篇 EXP，但只能定位为“手动深度审阅器”，不适合随编辑器连续触发。最终采用 4K 上下文和紧凑 Heap IR；完整 EXP 不截断。

## 最终配置

- LM Studio：context 4096、parallel 1、GPU offload 35%、不加载 mmproj。
- pwn宝：manual、input 3200、output 768、temperature 0.1、timeout 300s。
- JSON assistant prefill：开启。
- 单次候选：最多 2 条。

## 实测

- 输入：133 行、2908 bytes。
- 静态 IR：56 operations。
- 模型请求：3017/3200 input tokens。
- 完成时间：175.078 秒。
- 模型正确识别 `add(size,idx)` 的 `size/index` 角色，置信度 0.98。
- 模型对 `keywords` 和 `len` 角色的输出不够规范，严格 validator 拒绝/校正，没有直接污染 allocator。

## 已反馈学习

- `add(size,idx)`：modified feedback；`keywords=[]`，roles=`size,index`。
- `copy(src,dst,len)`：modified feedback；将角色 `len` 校正为 `length`。
- 学习后回放：add 规则匹配 27 次，copy 规则匹配 2 次。
- 精确规则必须匹配当前源码里的 helper 参数签名，避免其他题目的普通 `add(size,data)` 被错误套用。

## 主要证据

- `request_summary.json`
- `ai_result.json`
- `feedback_verification.json`
- `gui_smoke.json`
- `reviewed_feedback.jsonl`
- `static_operations.json`
