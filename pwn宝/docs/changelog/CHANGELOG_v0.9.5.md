# pwn宝 v0.9.5

## Sunshine EXP AST corpus

- 新增 `pwnbao.tools.sunshine_ast_corpus`，对 `sunshine 附件` 中所有 `exp* / exploit* / solve* / pwn*` Python 候选做只读 AST 扫描、allocator IR 回放和逐文件 JSON 留档。
- 本轮固定清点 52 个候选；输出位于 `artifacts/sunshine_ast_v095/REPORT.md`、`report.json` 与 `cases/*.json`。
- 报告明确区分 `heap_model_ready`、`partial_needs_allocation_profile`、`needs_challenge_behavior_profile` 和 `excluded_non_heap`，不把自定义 allocator / 隐式服务端 malloc 猜成 glibc 真值。

## AST 识别增强

- API helper 分类改为语义 token + 真实 I/O 证据，消除 `free_size_for_count`、`build_prompt`、`read_payload` 等子串误判。
- 支持 bounded transitive helper inlining：`exploit -> setup -> poison -> add/free` 不再只显示入口函数的直接调用。
- 支持唯一类方法的静态内联，可覆盖 `Exploit.run()` / `self.command()` 风格脚本。
- 支持完整 variadic dispatcher 推导：同一源码内 `cmd(choice, *values)` 同时具备 alloc/free/edit/show 四类证据后，按 literal choice 生成严格局部规则。
- 支持字面量 JSON/dict action：`capture/forget/recall/rewrite` 映射为 alloc/free/show/edit。
- 支持 `j_ / api_ / do_ / op_` 前缀 action helper，以及 UBW 风格 `trace/discard/reveal` 菜单包装。
- 支持 Python 字符串内嵌 JavaScript 的 `new/view/recycle/resize` 对象生命周期提取。
- 无调用或被 CLI 分支遮蔽时，可预览唯一有堆效果的非 `main` 入口；所有预览保持 inferred 标记。

## 安全与真实性

- 全程不 import、不 exec、不连接 EXP 目标。
- 所有循环与递归内联继续受 `max_loop_iterations / max_events / call depth` 限制。
- `heap_model_ready` 只代表 IR 可重放；地址/bin 精确真值仍需 binary behavior profile 或 pwndbg checkpoint。
