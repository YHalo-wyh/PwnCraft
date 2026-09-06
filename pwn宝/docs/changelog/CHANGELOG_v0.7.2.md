# pwn宝 v0.7.2

## Qwen 校正闭环加固

- 将 Heap AI prompt/cache 版本推进到 `pwnbao-heap-ai-v6-anchor-context`，避免旧的已拒绝候选缓存挡住新的校验逻辑。
- 兼容 Qwen 常见错包：当模型把 `{rule_id, arguments}` 误放进 `operation` 时，先规范化为受限 `heap_rule_call`，再由 validator 和 strict replay 处理。
- 支持从 compact timeline 文本中的 `Lx@start:end` 安全重绑源码切片；最终 `source_text` 仍必须来自 `exp_source[start:end]`。
- Strict replay 新增三类拒绝：
  - `allocator.consolidate` 必须绑定到 `free` 或已有 fastbin 状态。
  - `replace_operation` 不允许丢失已有静态事实，例如把已识别 data 的 alloc 替换成空 data。
  - `insert_before/insert_after` 不允许在同一源码范围重复插入已有 free/show/edit 等 Heap IR。

## 静态识别反哺

- 从 prompt role 推断中移除 `choice`，保留函数形参别名里的 `choice`；菜单提示 `choice:` 不再把 payload-only helper 误判成 index/free。
- 新增 `sendMessage(payload)` 回归：菜单号为 3 但没有 index 语义时，不进入 Heap IR。
- 继续保留零参 `delete()` 对最近 active chunk 的隐式绑定；pwn179 中连续 `delete()` 仍作为真实 double-free 利用意图展示。

## 语料结果

- `static_v6_all`：23/23 case completed，449 ops。
- 相比 `static_v4_all`，移除了由 `choice:` prompt 误判造成的 5 个假操作；`sendMessage` 不再污染 chunk/free 视图。
- Qwen `qwen_rules_v11`：3/3 case completed，0 个候选进入规则晋升；pwn166/pwn179 的候选均被 strict replay 作为负样本拒绝。
