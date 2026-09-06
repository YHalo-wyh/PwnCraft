# pwn宝 v0.7.3

## HeapViz GUI 收尾

- 从 HeapViz 控制区移除“利用路线/加载路线”入口，避免模板路线误导用户或污染左侧 EXP。
- 基础“语义操作”下拉只保留 `alloc/free/edit/show`；`copy/fake/unlink` 等复杂语义继续由 EXP 实时识别。
- 左侧黄色操作槽不再显示 `×N` 文本，保持拖拽槽轻量，不干扰 EXP 编辑区。
- “清空时间线”改为“回到 EXP 实时识别”，相关日志改成“自动语义块”，不再使用模板路线措辞。
- 自定义 Chunk 面板文案改为“教学标注层”，强调不改 allocator replay 结果。

## 软安决赛本地语料闭环

- 新增 `LocalSourceCorpusScanner`，支持从用户指定源码/Writeup 目录扫描 `.py/.md/.txt`。
- 产出 hash-lock 的 `manifest.json`、扫描索引 `source_index.json` 和 Qwen 用 `prompt_guidance.json`。
- `heap_ai_writeups` CLI 增加 `--kind auto|pdf|local`，PDF 目录继续兼容，源码目录自动走本地扫描。
- 本轮接入 `C:\Users\WYH\Desktop\软安决赛`：
  - 52 个文本文件；
  - 63 个源码/Markdown 片段；
  - 12 个 heap 语义 case；
  - 62 个 helper 候选；
  - 技术标签覆盖 `heap-general/tcache/unsorted-bin`。

## 静态识别反哺

- 从软安决赛 FSOP/Studentmanagement 样本中提炼 `login/select -> edit_bio(size, payload)` 形态。
- 新增 active-object edit 规则：已有 active selector 时，`edit_* / update_* / write_*` 字段写入使用 active index，不能把 size 参数误当 index。
- learned/helper mapping 路径也支持 `roles=["size","data"]` 的 active-object edit。
- prompt guidance 支持采集 class method helper，剔除 `self/cls`，并输出 `edit_bio(size,payload)` 的规则化范例。

## Qwen 提示词与门禁

- AI prompt 升级为 `pwnbao-heap-ai-v7-compact-rules`，压缩系统提示词以适配 4096 context / 3584 input 预算。
- v7 明确提示 active-object edit、copy roles、source span、Pwndbg observed 边界和 `heap_rule_call` 输出形态。
- strict replay 新增 op-rule 锚点门禁：`op.alloc/free/edit/show/copy` 的 `insert_before/insert_after` 不能锚到已识别的不同语义源码步骤。
- 实测拒绝了 Qwen 将 `op.show` 插到 `add(...)` 锚点后的候选，避免“可重放但源码锚点不诚实”的假阳性。
