# v0.15.0

Pwn Workbench 大改第一轮：主界面从「6 个平铺页签」重构为统一 Workspace 驱动的左侧一级导航工作台（规划 §五十五 / §五十六：Phase 0 收口 + Phase 1 交付）。

## 主界面导航重构

- 左侧新增一级导航栏，11 个目的地：`Dashboard / Binary / Stack / Heap / ROP / Libc / Format / Syscall / Debug / EXP / Tools`。
- 旧 `workspace_tabs` 的 Exp 编辑 / 堆可视化 / Pwndbg / IO FILE 全部迁入对应目的地；只有 EXP 页保留左侧工具列与底部日志，其余页面为全窗工作区。
- IO FILE 工作区完整保留，挂在 Libc 目的地下；日志 / 诊断挂在 Tools 目的地下。
- Stack / Libc / Format 为诚实占位页（Coming later + 所属 Phase 说明），无假按钮。

## 统一 Workspace（Phase 0 收口）

- `Binary` 页、`ROP` 页、`Syscall` 页、Dashboard 全部只读写共享 `PwnWorkspace`，跨页状态不再复制。
- Dashboard 页显示 Binary / Gadget / 变量的实时摘要；`Ctrl+K` 命令面板所有条目改为直达一级导航目的地。
- 新增 `.pwncraft` 项目打开/保存：Dashboard 按钮 + `project.save` / `project.open` 面板条目；`PwnWorkspace.merge_saved()` 在保持对象身份与订阅的前提下整体恢复静态事实，运行时数据自动标记 stale。

## QUERY 工具链（Truth Engine 落地）

- 新增 `pwncraft/core/cli_runner.py`：`CliToolService` 连接 CLI 注册表、执行器、解析器与 Workspace。WSL 未配置时只允许复制命令（执行报错），并保证 QUERY 工具永远不触碰 `exploit` 状态（有测试断言）。
- 新增 `pwncraft/core/static_facts.py`：`readelf -sW`（函数/导入/OBJECT）、`objdump -R`（GOT 槽位）、`objdump -d -j .plt`（PLT 桩）三个严格行格式解析器；任意文本不能伪造成事实。
- `WslToolRunner` 白名单扩充只读查询工具：`nm / strings / ldd / ropgadget / ropper / one_gadget / seccomp-tools`（patchelf 仍单独走原流程）。
- CLI 注册表补全中文参数说明（每个参数都有 `description_zh`，验收 #9），支持 `--file=` 粘合与位置参数；新增 `readelf.dynsyms / objdump.relocations / objdump.plt` 专用查询工具。

## ROP 页（§七–§十二）

- **ROPgadget Command Builder**：GUI 参数表单（Binary/Only/Filter/String/BadBytes/Depth/Range）实时生成命令预览，支持运行、复制命令、QSettings 预设保存/删除。
- **Gadget Explorer**：保留结构化列表与五星评分，新增 `pop rdi/rsi/rdx/rax/syscall/leave;ret/jmp rsp` 语义快捷入口。
- **Gadget Shelf**：收藏按角色进入 `workspace.gadgets.pinned`，支持复制地址、取消收藏（`unpin_gadget`）、GDB 定位。
- 页面无任何「插入 EXP」控件（有自动化断言，验收 #7）。

## Binary 页（§五十五.9）

- 「检查程序」一次执行 `checksec → readelf -sW → objdump -R → objdump .plt` 链，解析结果（保护、函数、导入、GOT、PLT）全部写入 `workspace.binary / workspace.symbols` 并带命令级证据。
- 三个符号表（函数/GOT/PLT）支持过滤与双击复制地址；ELF 头事实由 `BinaryInspector` 补齐。

## Syscall 页（§十四）

- 架构自动跟随 Binary 页的 `workspace.binary.architecture`。
- 新增 `seccomp-tools dump` 解析入口：策略写入 `workspace.syscalls.seccomp_policy`，作为全局约束供后续 ROP/ORW 消费（§十六）。

## 调试器联动（§四十）

- `DebuggerWorkspace.send_command()` 公开命令通道；Gadget/Shelf 的「GDB 定位」跳转 Debug 页并在真实 pwndbg-mogai 终端执行 `x/4i <addr>`，GUI 不重实现 pwndbg。

## 修复

- 修复命令面板排序不确定：按 命中字段权重（标题 > id > 目标 > 描述）+ 标题字典序稳定排序；修复 `search_palette("gadget")` 首项漂移的既有失败测试。
- 修复 `FunctionWorker` 信号连接 lambda 导致跨线程直接回调 GUI 的隐患：三处改为绑定方法槽（PyQt 自动队列连接）；worker 线程只计算，workspace 发布统一回到 GUI 线程执行。
- 修复主窗口构造期导航信号早于 `_exp_root_splitter_sizes` 初始化导致的启动崩溃。

## 测试

- 新增 `tests/test_workbench_v015_core.py`（CLI 服务/解析器/面板排序/Shelf/merge_saved/注册表中文说明）与 `tests/test_workbench_v015_gui.py`（页面行为 + QUERY 纪律）；MainWindow 级断言经 `tests/_v015_nav_probe.py` 子进程隔离执行。
- 全量回归：**312 passed, 1 skipped**（连续两次）；heap 语义基准 60/60 PASS；旧 Heap / EXP / Debugger 功能无回归。

## 已知边界

- ROP Chain Builder / ret2libc / ORW / SROP 属 Phase 2/3，本轮未实现（`pwncraft/core/rop.py` 的 Chain 模型与寄存器模拟已就绪待接入）。
- Stack / Libc / Format 页为规划中占位；Palette 中对应条目已标注「规划中」。
