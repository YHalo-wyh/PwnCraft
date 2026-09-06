# v0.19.0

本轮一次性完成总规划全部剩余阶段：Phase 4（Libc）→ Phase 5（Heap 深化）→ Phase 6（Format String）→ Phase 7（Exploit Workflow）→ Phase 8（AI Tutor 第一步）。至此《PwnCraft下一代 Pwn Workbench 大改开发任务》八个 Phase 全部落地。

## Phase 4：Libc Workspace（§二十五/§二十六）

- 新增 `pwncraft/core/libc.py`：
  - `parse_one_gadget_output()`：结构化 one_gadget 输出（地址/调用/约束），`[` 开头的约束行完整保留，掩码/内存类约束在检查时判 unknown。
  - `check_one_gadget_constraints()`：只对照运行时报告的真实寄存器评估 `reg == NULL`；缺寄存器或内存表达式（`rsp+0x40`）永远 unknown——没有 oracle 就不推荐「可用」。
  - `parse_build_id()`：从 `readelf -n` 提取 Build ID，用于确认 libc 与题目配对。
- CLI 链新增 `readelf.notes`（Build ID）与 `one_gadget` 两个 QUERY 工具解析；`CliToolService` 入库 `binary.libc_build_id` / `libraries.one_gadgets`。
- `PwnWorkspace.set_libc_symbols()`：libc 文件符号偏移独立存放于 `libraries.libc_symbols`（不与二进制符号混淆），全部经真实 `readelf -sW`。
- Libc 页「后续计划」占位替换为真实 `LibcWorkspacePanel`：路径输入 → 解析（符号 + Build ID，单 worker 双查询）、Symbol Browser（过滤 + 双击复制偏移）、one_gadget 表（地址/调用/约束/对照运行时寄存器的判定：可用/不满足/未知）、libc_base 摘要；`workspace_merged` 刷新。

## Phase 5：Heap 深化（§二十八/§二十九）

- 盘点确认既有 HeapViz 已满足 Operation Timeline（时间线点击回放）、State Replay、Memory Diff（WriteImpact before/after + set_diff）——不推翻。
- 新增缺口能力：`PwnWorkspace.record_heap_stage()` 把当前堆快照按 step 去重记录为 Exploit Stage 输入；HeapViz 渲染快照时自动调用（同 step 校准不重复入库），allocator 仍是详细真值所有者。
- `PwnWorkspace.add_primitive()`：Primitive 模型（§三十三）入库 `exploit.primitives`，同名单覆盖、带 evidence/source/state。

## Phase 6：Format String Lab（§二十七）

- 新增 `pwncraft/core/fmtlab.py`：
  - `find_fmt_offset()`：确定性地解析探针输出中 0x41414141 标记的 %p 位置（64/32 位双匹配语义）；absence 返回 None，不是 0。
  - `plan_fmt_writes()`：%hn 两字节分解（纯算术，逐半字 address/part），负地址/越界值拒绝；`to_pwntools()` 生成 `fmtstr_payload(offset, {target: value}, write_size='short')` 骨架——padding 数学委托 pwntools，本侧只产出可证明的分解。
- Format 导航页占位替换为 `FormatLabPage`：Offset Finder（探针粘贴 → 偏移，同步 Write Planner 偏移框）+ Write Planner（计划 → Preview → 确认插入，Ctrl+Z 可撤销）。

## Phase 7：Exploit Workflow（§三十四/§三十三）

- 新增 `pwncraft/core/capability.py`：纯规则式 `analyze_capabilities()`，只消费 Workspace 事实：
  - Control RIP：overflow_offset 或已记录 Primitive；
  - ret2libc：pop rdi + got/plt 符号对 + libc_base；
  - ORW：seccomp 明文 execve BLOCKED 且 open/openat-read-write 可用；
  - SROP：syscall Gadget + rax/rsp 控制证据；
  - Return-to-main：main 符号 + ret + NX ON。
  每个 verdict 携带 reasons 与 missing，state 只有 available/blocked/unknown；空 Workspace 无可用路径。
- Dashboard 新增「能力分析」面板：✓/✗/? 列表 + reasons + 缺失项，随 binary/gadgets/stack/seccomp/symbols/primitives/libc 事件实时刷新；纯规则，AI 不参与判定。

## Phase 8：AI Tutor 第一步（§四十一/§四十二/§四十五）

- Dashboard「AI 解读（本地模型，手动）」：把结构化 Workspace 摘要（binary/security/variables/gadgets/leaks/stages/capabilities…）+ 规则式能力判定交给既有 `OpenAICompatibleProvider`（复用 ai/base_url、ai/model 等 QSettings 配置），请求明确指令「不得编造任何地址或事实」；模型输出仅作为解释文本弹窗展示，不回写 Workspace、不触发自动分析。
- 三层架构归位：Truth Engine（工具事实）→ Exploit Engine（规则判定）→ AI（解释）。没有一键自动 pwn。

## 验证

- 新增 `tests/test_phases_4_8_core.py`（16 项）与 `tests/test_phases_4_8_gui.py`（4 项）。
- 全量回归：**369 passed, 1 skipped**；Heap semantic benchmark 通过；导航探针 NAV PROBE PASS；py_compile 通过。
- 官方 pwndbg 未修改；QUERY 页仍无 EXP 插入；BUILD 页全部 Preview→确认→Undo。

## 遗留边界（如实声明）

- one_gadget 约束中涉及内存的表达式（rsp+offset）需要运行时内存 oracle，目前恒为 unknown。
- main_arena 偏移、libc 数据库（如 libc-database 查询）未实现；版本号沿用任务配置，Build ID 为真实工具输出。
- fmtstr payload 的 padding 字节由 pwntools 运行时生成，本侧不计算。
- AI 解读依赖本地 LM Studio 在线；离线时按钮报错并保持功能不变。
- syscall chain 动态 fd 数据流自动传递仍未做（open 返回值 → read 需用户确认）。
