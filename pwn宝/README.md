# PwnCraft

> 当前版本：**Electron Workbench 为唯一主程序**

PwnCraft是一个 Windows 优先的 CTF Pwn EXP 工作台，**当前主程序为 Electron Workbench**（`pwnbao-electron/`）：
Electron 壳 + Monaco（EXP 编辑器）+ xterm.js/node-pty（多实例终端）+ Python 真值桥
（`pwnbao.electron_bridge`，30+ stdio JSON-RPC）。Electron 端永远只是表面，所有 Pwn 真值
（allocator 仿真、gadget 解析、约束校验、libc 推导）都在 Python 层。

启动：

- Windows：双击 `启动新版.bat`
- PowerShell：运行 `./启动新版.ps1`
- 手动：

```bash
cd pwnbao-electron
npm install        # 首次
npm start          # 完整工作台
npm run smoke      # 无头冒烟（桥 + 终端）
```

功能面（10 页）：概览/导入 · Binary（WSL 真实 CLI）· EXP 编辑器（代码块/转换/格式化/命令/GDB 工具列）·
**Heap 物理堆画布**（16 模板 + EXP 回放，全部经 `GlibcHeapEngine` 真实 glibc allocator 仿真；
JS 弹簧-质量物理引擎动画；画布校正即时回放并**自动推断识别规则**）· IO FILE（glibc 布局 + 约束校验）·
ROP（ROPgadget 真实执行 + Shelf + Chain/ret2libc/SROP + 终端直接可用）·
调试（**新开终端实例自动进入 pwndbg-mogai + ELF**，隔离 fork、官方 pwndbg 零改动）·
Format（偏移/写入计划）· Syscall/ORW · Stack/Leak（cyclic + libc_base 推导）· 工具箱。

旧桌面栈、PyInstaller 构建产物和旧截图探针已清理；真值层（`PwnWorkspace` / CliToolService / `PhysicalMemory -> Typed Views`）继续由 Electron 的 Python 桥使用，`third_party/pwndbg-mogai` 独立 Fork 不受影响。

早期架构与各阶段变更见 [`ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md)、
`docs/changelog/CHANGELOG_v0.30.1.md` 与 `docs/changelog/`（v0.2.0 起）。

## 目录结构

```text
pwnbao/            源码主包（features / core / tools + electron_bridge）
pwnbao-electron/   Electron Workbench（唯一主程序：壳 / 渲染层 / node-pty 终端）
tests/             自动化测试（pytest）
third_party/       pwndbg-mogai 独立源码 Fork（源码的一部分）
datasets/          基准数据集
pwnbao/core/session/  TargetContext 单一 Target 真值
docs/
  architecture/    架构与设计文档（ARCHITECTURE / DEBUGGER / PWNDBG_FORK / HEAP_* …）
  changelog/       版本更新记录（CHANGELOG_v0.2.0 起）
  validation/      各版本验收记录（VALIDATION_* / 验收报告）
  plans/           历史迁移计划（MIGRATION_PLAN_v0.11 ~ v0.13）
artifacts/         构建与评测产物（attic/ 为退役归档；ui_audit_v*/ 截图验收）
```

## Workbench 导航（v0.15）

- **Dashboard**：目标优先入口（检查程序 / 找 Gadget / 构造 ROP / 绕 Seccomp …）、项目打开/保存（`.pwnbao`）、变量面板与实时摘要。
- **Binary**：一次执行 `checksec / readelf -sW / objdump -R / .plt`，保护、函数、GOT、PLT 解析入库并带命令级证据。
- **ROP**：ROPgadget Command Builder（参数表单 + 实时命令 + 预设）、Gadget Explorer（语义快捷查询 + 五星评分）、Gadget Shelf（角色收藏 / 取消收藏 / GDB 定位）。
- **Syscall**：Explorer 三架构查询 + Seccomp 全局解析；Planner 给出寄存器/Seccomp/缺失 Gadget 诊断；ORW Builder 与 SROP Builder 均为全事实可执行才允许 Preview 后插入 EXP（帧布局由 pwntools SigreturnFrame 提供）。
- **Stack**：Phase 2 已完成 Offset Finder、Stack Canvas、Leak Manager、ROP Chain/ret2libc 联动；支持 cyclic 偏移、共享 Chain 和 libc base 派生。
- **Libc**：真实 `readelf` 符号提取 + Symbol Browser、one_gadget 约束解析（只对照运行时寄存器判定，缺 oracle 恒为未知）、Build ID 配对、libc_base 摘要；IO FILE 工作区同页。
- **Format**：Offset Finder（探针标记定位）+ Write Planner（%hn 分解本地计算，payload 数学委托 pwntools），Preview 后插入。
- `Ctrl+K` 命令面板直达以上所有目的地；面板排序按命中字段权重稳定决定。


## v0.10 Allocator Truth Model

- **Memory-driven**：chunk `size/PREV_INUSE/prev_size`、backward/forward consolidation、tcache entry `key/next`、safe-linking decode、top `prev_size/size`、unsorted/smallbin/largebin victim `fd/bk` integrity check。攻击者写进 `PhysicalMemory` 的字节会被下一次 allocator 操作直接读取。
- **Cache-driven but audited**：tcache/fastbin head/count、bin bucket 索引和 expected ordering 仍保留 Python 容器用于 arena cache/UI/性能；链中 next 与双链 victim 字段不由 cache 覆盖。`assert_cache_consistency()` 与 `HeapSnapshot.model_divergences` 只报告分裂，不静默修复。
- **AllocatorAbort**：tcache duplicate、fastbin top duplicate、双链损坏、top unknown/too-small/misaligned/PREV_INUSE 异常形成结构化终止结果，UI 展示 reason/check/address/metadata/policy。
- **Overwrite semantics**：普通 user write 与 metadata corruption 分层；impact 保存字段内 offset、实际覆盖长度、payload offset/length、before/after 和完整字段 byte mask。top 也是正常 `MemoryObject`，不是 House 名称触发的 side channel。
- **Fake Chunk Evidence Levels**：结构兼容 payload 只记 `candidate`；allocator 实际 free/reference 后才为 `confirmed`。普通 ROP/FILE/ucontext 词序不会因“四个 qword”直接被确认成 fake chunk。
- **Benchmark Methodology**：`datasets/semantic_benchmark/v0.10.json` 含 60 个 checked-in、人工独立标注 case；whole-case 必须让所有声明真值同时通过。新增 metadata/consolidation/tcache duplicate/top/freelist/integrity abort/partial overwrite 指标。
- **Corpus level**：批量报告严格使用 `PARSE_ONLY / MODEL_READY / PARTIAL_REPLAY / FULL_REPLAY / SEMANTIC_VERIFIED`；只有外部 oracle 文件才能进入 `SEMANTIC_VERIFIED`，模拟器不能给自己认证。

## 功能

- 高 DPI 桌面工作台：使用 paper/ink/khaki/clay/sage/mist 低饱和配色、细分隔线和紧凑的编辑式组件；不使用会挤占内容区的大按钮或装饰图标。
- 首次运行使用独立引导页配置目标环境、本题文件和 EXP 习惯；保存后自动持久化，后续启动直接进入工作台。
- 增加单实例锁和本地激活通道；重复点击快捷方式只会唤起已有主窗口，不会再创建第二个工作台。
- 全局只保留一档经过 Windows DPI 校准的 100% 逻辑密度；移除缩放选择器和快捷键，避免 旧桌面缩放与系统缩放叠加导致文字被截断。主窗口和 splitter 位置仍自动保存。
- 主界面只保留一行 `Exp 编辑 / 堆可视化 / Pwndbg / IO FILE / 日志 / 诊断` 导航；顶部重复菜单已删除。
- HeapViz 保持左上 EXP、左下 Context Editor、中间 Physical Heap、右侧 Bin/Show。Context Editor 仅有 `当前操作 / 字段编辑 / 函数适配`；自定义显示 overlay、Timeline、Before/After 和 AI 校正不再挂载到 Heap 页。
- v0.10.2 默认三栏约为 `550 : 755 : 252`（1600px 审计窗口）；地址轴缩至 112px。物理堆和 Bin/Show scene 在首次显示与 resize 时优先 fit 宽高，普通场景默认不需要横向或纵向滚动；超大 trace 到达可读字号下限后才保留滚动。
- 画布证据文本不再调用 `elidedText`。短栏内会逐级降低字号至可读下限，但不会把 `copy-overlapped` 显示为 `copy-overl…`；chunk role 改在 header 独立第二行显示，不再和 `idx/size` 抢同一小段宽度。
- 拖拽代码块生成 pwntools Python 片段，支持参数占位符填写。
- 内置基础 pwn 模板：本地/远程连接、ELF/libc 加载、cyclic、ret2win、ret2libc、格式化字符串、p64/u64、菜单题 IO、调试片段。
- 进制转换：按当前任务的 32/64 位生成 int 强转、有符号/无符号强转、p32/p64、u32/u64、int.from_bytes、low/high half-word 和 64 位四段 half-word；可填写变量名直接生成 `low  = system_addr & 0xffff` 这类片段。
- 格式化字符串辅助：当前默认收敛为模块化片段，可分别插入 `low/high`、`p32(addr)+%s` 泄漏 payload、两次 `%hn` 写入 payload；发送方式可选 `send/sendline/sendafter/sendlineafter/只生成payload`，不插入整份 exp。
- 初始代码头会按引导生成 `from pwn import*`、`import time`、`context`、你的默认 `context.terminal`，以及 `elf=ELF('./pwn')` / `libc = ELF('./libc.so.6')` 风格加载；自定义 base64 是独立代码块，不默认插入。
- 命令提示：按当前路径生成 WSL 命令文本，包括 checksec、file、readelf、objdump、ROPgadget、ropper、one_gadget、seccomp-tools、patchelf 等；点击选项即复制，不在软件内执行。
- C 函数速查：工具箱右列速查卡（左侧为编码转换/环境体检/命令提示三卡竖排）+ EXP 工具列 `C 函数` tab（Ctrl+K 直达）。内置 312 个 pwn 常用 C 库函数/符号，覆盖 18 个分类：输入输出（printf 系 / scanf 系 / fopen·fdopen·fileno / setvbuf / getline / fmemopen / __isoc99_*·_*_chk 符号形态…）、字符串（str* 族 / mem* 族 / 正则 regcomp·regexec / strchrnul 等 GNU 扩展 / BSD 老接口）、内存（malloc 系 / sbrk / mmap / mprotect / malloc_trim / __stack_chk_fail / __malloc_hook·__free_hook 数据符号）、文件描述符（open / read / write / dup2 / pipe / pread / fcntl / ioctl / sendfile / readv·writev…）、文件系统（stat / realpath / opendir·readdir / chmod…）、进程执行（system / exec* / fork / clone / ptrace / prctl / syscall 通用调用 / __libc_start_main / memfd_create·fexecve / wordexp…）、网络套接字（socket 全家桶 / inet_* 地址转换 / 字节序 / select / poll / epoll / sendmsg·recvmsg）、数值转换（atoi / strto* 族）、随机数（rand / getrandom）、错误诊断（errno / perror / strerror / assert / backtrace）、信号处理（signal / sigaction / kill / alarm）、系统环境（time / getenv / environ 数据符号 / uid 切换 / rlimit / setlocale）、字符处理（ctype 全家）、排序查找（qsort / bsearch）、非局部跳转（setjmp / longjmp / ucontext 全家含 setcontext+61）、数学（abs / sqrt / pow…）、线程（pthread 族：多线程堆题 / arena 触发）、动态链接（dlopen / dlsym / dladdr / dl_iterate_phdr），另附 8 个位/逻辑运算符速查表；每个函数按「原型 · 头文件 · 参数逐项说明 · 返回值 · pwn 笔记」展示，支持搜索、分类过滤与命中计数；数据在 `pwnbao/data/clib_catalog.json`，与代码块目录同一加载/校验模式（`CFunctionCatalog`，经桥 `clib_catalog` 提供）。
- GDB 菜单：点击常用 GDB/Pwndbg 指令即复制；`gdb.attach(io)` + `pause()` 保留为固定代码块。
- 堆可视化工作区：切换后自动隐藏主界面的积木库和运行记录，形成“左侧完整 EXP、右侧 Heap/Bin 图”的专注布局；主 Exp 编辑器与 Heap 页共享同一份 Monaco 文本模型。
- Heap 图按低地址在上、高地址在下排列；左侧地址栏位于画布外。左侧地址轴只显示相对 heap base 的 `+offset`，绝对地址仅放在 tooltip 和详情中；非堆目标单独放到 `target / non-heap` 区。
- EXP 识别器已换为完整模块 AST 分析：支持多行/分号调用、位置与关键字参数、`*args/**kwargs`、方法调用、函数别名和 wrapper，并可展开 `range/list/tuple/enumerate/zip`、有限嵌套循环、解包和列表推导式。它只安全求值 AST，不执行 EXP 函数、属性或任意 Python 代码。
- `chunks.append(add(...))`、`idx = add(...)`、`delete(chunks[i])`、`data = show(7)`、`show(7); data = io.recvline()` 以及 `u64(data[:5].ljust(8,b'\x00')) << 12` 会形成连续的值流和源码绑定。每个派生值保留依赖、字节宽度、端序与 provenance。
- “函数适配”页支持直接粘贴题目中的 helper 定义，也支持行为模型 JSON：一次菜单 helper 可确定性展开成 0/1/N 个内部 malloc/free/edit effect。无效 effect、重复 helper 或错误 JSON 会明确报错并保留上一次有效模型，不会静默降级或覆盖 EXP。
- 独立 `BIN / SHOW` 区域统一绘制 tcache、fastbin、unsorted、smallbin、largebin 的链头、节点、fd/bk 方向以及 show/派生值卡片；它与物理堆独立滚动，点击 bin 节点仍会联动选中对应 chunk。chunk 详情同时显示 `chunk_addr`、`user_ptr`、物理块 ID、菜单 handle 状态和字段来源。
- 非堆 EXP 不会因 `payload`、`bytes.fromhex`、`ljust`、`sendafter` 或 shellcode 字节被猜成 chunk。当没有可证明的堆语义时，中栏显示保守空模型说明，而不是一张伪造的堆图。
- allocator 内部始终使用可验证的 glibc 状态重放；`malloc_to_target` 只是期望，实际返回地址必须由 tcache/fastbin/unsorted/smallbin/largebin/top 状态推导，allocator abort 后不再伪造后续状态。界面不再显示“进阶 · 严格 glibc”这类无意义标签。
- 基础 allocator 状态机会处理 tcache/fastbin 复用、unsorted 扫描与切分、regular-bin 整理、largebin best-fit 近似、top 合并以及 `malloc_consolidate` 后的物理相邻 coalesce；旧菜单索引会保留为 dangling/alias，物理块复用不会再创建两个互相矛盾的“真实 chunk”。
- 对真实 EXP 的 UAF 写入会尝试自动识别 freelist poisoning。例如 freed tcache 上的 `edit(0, p64(target ^ (fd_pos >> 12)))` 或先计算 `encoded_fd` 再写入，会把后续同 size malloc 按 safe-linking 链推进。无法证明时只提示候选，不强行画成功。
- “路线”页提供不带利用假设的 chunk header/地址布局和 `C -> B -> A` tcache 入链演示；高级路线使用“支持/有条件/不支持”文字状态，不用装饰符号。
- Pwndbg 工作区直接启动 `third_party/pwndbg-mogai`。普通 `ni/si/x/frame/vmmap` 只走 PTY；仅 allocator dirty、内存写、信号或显式 heap 命令延迟触发 Runtime Snapshot。
- 语义被分成 program / corruption / intent 三层：alloc/free/edit/show/copy 是实际程序事件；header/fd/fake chunk 是内存破坏事实；定向 malloc、main_arena leak、stdout、setcontext 等是利用意图。严格模式不会让 intent 直接篡改 allocator 事实。
- 时间线显示源码、语义、chunk/index、size/data、状态变化与可信度。未知 `if/else` 只重放共同前缀，选择候选路径后才继续；双击或右键可校正、忽略、拆分、合并和插入人工步骤，也可把 EXP 选区直接绑定为语义步。
- chunk 内存使用 `MemoryRegion` 标记 known/zero/unknown/metadata 和 provenance：malloc 未初始化尾部显示 `unknown / not observed`，不再伪写为 NULL；已知非零机器字全部展开，只有可证明的连续零字节才在卡片中央折叠。右侧默认就是详细证据视图，不再从 `operation.data` 拼出“payload 概要”伪装成内存。
- v0.9.1 的写入路径为 `PayloadIR -> WriteEvent -> PhysicalMemory -> TypedMemoryView`。`edit(0, b'A'*0x28+p64(0x51))` 会真实写过 A.user，并让相邻 B 的 `prev_size` 和 `size` 从同一份物理内存立即变化；详情页显示 payload offset、物理范围、before/after 与最后 writer。
- `p8/p16/p32/p64`、拼接、重复、`flat/fit` 字典、显式 filler、`ljust/rjust`、`bytes/bytearray`、`int.to_bytes`、`struct.pack`、slice 和 join 会形成保留 offset/长度/端序/符号值的 PayloadIR。稀疏 `flat` 的默认 filler 标为 inferred，不伪装成零字节。
- tcache/fastbin 的 next 在插入时写入 PhysicalMemory，malloc pop 时再从物理字段读取并 safe-link decode；旧 `_pending_target_by_size` side channel 已移除。bin 中出现的外部 poisoned head 是 allocator 头状态，不是攻击名称触发的快捷结果。
- overlap 是“一份 PhysicalMemory，多份 chunk typed view”。从任意别名写入会同步改变所有覆盖同一地址范围的视图；scene group 明确携带共享物理对象 ID。画布按物理边界切段：单 owner 区间沿用该 chunk 的稳定颜色，多 owner 区间统一切换为 clay overlap 色；所有 alias 以非按钮色签完整列出，物理内存卡只绘制一次。
- 双链 bin 用 `bk | chunk | fd` 节点和上下弧线展示循环链；safe-linking 链尾按真实的 `PROTECT_PTR(pos, NULL)` 建模，现代 tcache 同时显示 key 字段。Bin/Show 区域永远位于物理堆右侧，不再根据视口宽度改成堆下纵向布局。
- unsorted/smallbin/largebin 现由显式 `insert/remove` transition 只改写必要的 arena/chunk 链接字段；UAF 写入的 fd/bk 不会被下一次画面刷新抹掉。fastbin/smallbin 的 tcache refill 和 largebin 不同 size 代表的 nextsize 环也有可回放事件。
- 可选本地 AI 协同识别：HeapViz 的“AI 分析”工具连接 LM Studio/OpenAI-compatible 服务，默认 Base URL 为 `http://127.0.0.1:1234/v1`，通过 `/models` 发现模型并调用 `/chat/completions`。未启动 LM Studio 时静态 AST 和堆模拟完全不受影响。
- AI 默认为手动深度分析：编辑 EXP、修改指令、连接模型都不发起请求，只有明确点击“分析当前 EXP”才会提交完整 EXP、压缩静态 IR、诊断和相关正负样本。每个模型候选都会由本地监督器在私有 allocator 中再次重放；无效锚点、no-op、丢失事实或引入新 allocator 错误的候选会自动隔离并记为负反馈，不需再次询问。监督器只能删除候选，不能自动修改 EXP 或堆状态；通过的候选仍由你决定应用/学习/拒绝。
- v0.7.1 的 Qwen 校正闭环增加受限 Heap Rule Catalog：模型只能调用 alloc/free/edit/show/copy、safe-link fd、header overflow、fd poisoning、fake chunk 和 consolidate 等声明式规则；规则展开为 Heap IR 后仍须通过 validator 与独立 allocator replay，不能直接修改 chunk/bin/画布。
- 严格通过的候选可生成最小 regression fixture 和确定性 helper 规则证据；只有至少两个独立 case、无已审核负样本且 holdout 通过才会全局启用。仅把 `0x90` 改写成 `144` 或改变字符串引号的等价候选会被视为 no-op，不进入反馈库。
- 未能从 EXP/Pwndbg 证明 request size 的 helper（例如 `reg(sid, name, password)`）不会被猜成固定 malloc size；布局会显示唯一的 `unknown-layout` 地址，free 后 bin/fd/bk 保持 unknown，不伪造 unsorted 链。只有真实快照或明确 size 事实才能进入 allocator truth。
- 提交前显示 tokenizer-free 保守预算：默认 4096 context、3584 input 上限、512 output 保留、180 秒超时；先精简重复 Heap IR，仍超限才停止，始终不截断完整 EXP。单次只请模型返回最有价值的 2 个候选。
- “应用并学习”会把 helper 签名、参数角色和无字面量 AST 调用形态保存为确定性规则；模糊代码只作为 few-shot 样本，拒绝结果会抑制重复建议。知识库可查看、停用、删除规则，并导出 JSONL 给外部 LoRA/微调流程。
- AI 知识默认保存到 `%LOCALAPPDATA%\pwnbao\ai\knowledge.sqlite3`，仅持久化候选相关源码片段，不保存整份 EXP；API token 只存在当前进程。非 loopback Base URL 会明确提示完整 EXP 将被发送。
- `ELF 工具` 菜单和 Pwndbg 拖放区会自动寻找 ELF 同目录的 `ld-linux*.so* / ld-*.so*` 与 `libc.so.6 / libc-*.so*`，通过 WSL `patchelf` 设置 interpreter、`$ORIGIN` rpath 和必要的 `DT_NEEDED` 替换。原 ELF 同名覆盖，操作前生成微秒级时间戳 `.bak.*`；interpreter/rpath/needed 任一验证失败即回滚。
- Pwn宝仅调用独立 `pwndbg-mogai`：source/runtime/config/cache/data 全部位于 Pwn宝命名空间；官方 `pwndbg`、`.gdbinit`、插件和更新方式完全不改。portable runtime 仍固定为 `2026.07.29` 并校验官方 SHA256。

## 运行

    cd C:\Users\WYH\Desktop\pwn宝\pwn宝\pwnbao-electron
    npm install        # 首次
    npm start

前置：Node.js（npmmirror 镜像）与系统 Python 3（真值桥 `pwnbao.electron_bridge`，标准库即可；
AI 语料工具需要 `pip install -r requirements.txt`）以及 WSL（CLI 工具 / pwndbg-mogai 均真实执行）。

## LM Studio 接入

1. 在 LM Studio 中加载一个支持 JSON 输出的本地模型并启动 Local Server（常用端口 `1234`）。
2. 打开“堆可视化 → AI 分析 → 设置”，保留 `http://127.0.0.1:1234/v1` 或填写其他 OpenAI-compatible Base URL。
3. 点击“连接”发现模型；连接成功后仍不会自动分析，需明确点击“分析当前 EXP”。
4. 逐条检查候选差异和 STRICT PREVIEW；普通“应用”只作用于当前场景，“应用并学习”才会写入全局反馈/规则库。

### Qwen3-Coder-30B-A3B-Instruct-Q4_K_M 本机实测预设

- 当前接入的模型 ID 为 `qwen3-coder-30b-a3b-instruct`，主文件约 18.63GB。它是 MoE Coder 模型，约 3B 参数激活，比先前选错的稠密 27B 更适合 EXP/AST/Heap IR 结构化分析。
- i9-14900HX / 32GB RAM / RTX 4060 Laptop 8GB 实测预设：4096 context、parallel=1、GPU offload 30%、Flash Attention、不加载 `mmproj`。模型加载后显存约占 7.5GB，35% 及以上对 8GB 显存过于紧张。
- PwnCraft默认使用 3584 input + 512 output、temperature 0.1、180 秒 timeout 和手动分析模式。本地题目完整 EXP 实测约 17–55 秒；不建议每次编辑都自动调用。
- 请直接使用上述模型 ID，不再使用 `pwnbao-qwen-coder` 别名，避免 LM Studio 的模型元数据解析异常。

接口与 LM Studio 的 [OpenAI Compatibility Endpoints](https://lmstudio.ai/docs/developer/openai-compat) 一致，不需要安装 `openai` Python 包。

## Heap AI 语料评测

仓库基准清单位于 `datasets/heap_ai/manifest.json`。本地 EXP 只按绝对路径和 SHA256 读取，不复制进仓库；how2heap 来源锁定 MIT commit。批处理支持按 split、case、SHA256 缓存和断点恢复：

    python -m pwnbao.tools.heap_ai_corpus datasets/heap_ai/manifest.json `
      --output artifacts/heap_ai_corpus/latest `
      --knowledge artifacts/heap_ai_corpus/latest/knowledge.sqlite3 `
      --allow-network --split train --case local.traditional.exp

加入 `--with-ai` 才会校验并调用精确模型 `qwen3-coder-30b-a3b-instruct`。LM Studio 未启动、模型不匹配、输入超预算和响应格式错误会分别记录为 `offline`、`model`、`over_budget`、`response`，不会影响静态识别；超预算时只压缩重复 IR，不截断完整 EXP。

本地 PDF WriteUp 可先生成只含哈希、来源页、修复后 Python 片段和派生 case 的清单；原 PDF 不会复制到项目：

    python -m pwnbao.tools.heap_ai_writeups F:\PWN\PWN\99PWN\00_WriteUp `
      --output artifacts\heap_ai_writeups\latest

再对生成的 `manifest.json` 运行静态或 Qwen 批处理。加入 `--auto-review-proven` 时，也只有 confidence 不低于 0.9、源码 hash/锚点有效且 strict replay 成功的候选会写入 fixture/rule evidence；这里的“训练”是可审计的规则、反馈与 holdout 闭环，不是 LoRA 或模型权重微调。

## 模块结构

    pwnbao/core/workspace          统一 PwnWorkspace、事件总线、TypedAddress、.pwnbao 持久化
    pwnbao/core/tool_actions       QUERY/DERIVE/BUILD/VERIFY/RUNTIME Action 类型系统
    pwnbao/core/cli_registry       CLI 工具注册表（中文参数说明）与命令构造
    pwnbao/core/cli_runner         CliToolService：执行 → 严格解析 → Workspace 入库
    pwnbao/core/static_facts       readelf/objdump 输出的结构化符号解析器
    pwnbao/core/workbench          BinaryInspector、GadgetExplorer、SyscallPlanner、编码与命令面板
    pwnbao/electron_bridge         Electron 真值桥（stdio JSON-RPC，30+ 方法）
    pwnbao/features/blocks        代码块、占位符和代码块渲染入口
    pwnbao/features/conversion    进制转换、p32/p64、u32/u64、signed/unsigned 结果
    pwnbao/features/fmtstr        格式化字符串 payload 生成器
    pwnbao/features/commands      WSL 命令提示和 GDB/Pwndbg 指令模板
    pwnbao/features/ai            LM Studio Provider、Heap Rule Catalog、严格校验、语料与 SQLite 反馈库
    pwnbao/features/heapviz       堆操作 IR、glibc 配置、模拟重放和代码生成
    pwnbao/features/heapviz/memory     稀疏 PhysicalMemory、地址空间、provenance
    pwnbao/features/heapviz/payload    PayloadIR 与安全 AST payload evaluator
    pwnbao/features/heapviz/events     alloc/free/read/write/overwrite 因果事件
    pwnbao/features/heapviz/views      从 PhysicalMemory 读取的 typed chunk views
    pwnbao/features/heapviz/benchmark  ground-truth semantic benchmark 与指标
    pwnbao/features/heapviz/bridge_session  Electron 无头堆会话（校正→回放→规则学习）
    pwnbao/core/elf_runtime         同目录 runtime 发现、patchelf 验证与回滚
    pwnbao/core/pwndbg_manager      固定 portable release 下载、SHA256 验证与 WSL 启动

## 测试

    python -m pytest tests/ -q

独立语义 benchmark 不以“没有崩溃”为通过条件，而是逐项核对 operation、参数、payload span、write range、overwrite field、allocator checkpoint、bin membership、物理字段值、bin transition、metadata/consolidation/tcache duplicate/top/freelist/integrity abort/partial overwrite：

    python -m pwnbao.tools.heap_semantic_benchmark

回归同时覆盖 AST 变体语料、安全求值、分支选择、人工校正重绑、MemoryRegion 真实性、request2size、bin 复用、safe-linking、Pwndbg diff、EXP/时间线联动、NULL 折叠居中，以及假 LM Studio 的模型发现、结构化输出回退、认证、超时/缓存、generation、私有严格重放监督、负反馈和精确学习规则。

## 打包

Electron 打包链（electron-builder）尚未引入，当前以源码运行（`npm start`）。

## WSL 依赖

第一版按你的 WSL 工具链生成命令提示。当前重点覆盖：

    patchelf
    file
    checksec
    readelf
    objdump
    seccomp-tools
    ROPgadget
    ropper
    one_gadget
    gdb / pwndbg
    python3

普通“命令提示”仍只复制文本；只有明确的 ELF/Pwndbg 菜单与 ELF 拖放流程会调用 WSL 内的 `patchelf` 和固定版 Pwndbg。

## 安全边界

- PwnCraft不会执行右侧代码框里的 exp 文本。
- PwnCraft不会主动连接远程题目服务。
- PwnCraft只在用户明确选择/拖入 ELF 时执行 patchelf；原名写回前会备份，并在验证失败时自动回滚。
