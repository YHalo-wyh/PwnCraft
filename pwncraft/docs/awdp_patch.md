# AWDP Patch（ELF 字节级补丁）设计说明

版本：v0.33 起提供。入口：Electron Workbench 活动栏「AWDP Patch · ELF 补丁」。

## 边界与数据流

- 真值在 Python：所有地址↔偏移换算、指令字节、rel32 位移、BPF 过滤器全部由
  `pwncraft/features/patch/` 生成，renderer 只展示与转发请求，不在 JS 里算任何字节。
- 原始 ELF 只读：补丁只写 `.pwncraft/runtime/` 工作副本；应用和撤销前自动生成
  `<name>.patchbak.<微秒时间戳>` 整文件备份，按应用批次原子撤销，记录持久化在
  `<目标目录>/.pwncraft/patch_log.json`。
- 完整性保护：补丁管理会实时核对工作副本，区分「已生效 / 已恢复 / 冲突」。只有
  全部记录仍然生效时才允许撤销或导出，避免外部编辑后覆盖未知字节；已由外部工具
  恢复的完整补丁组可清理；多段补丁只恢复一部分时会保留全部记录并提示继续处理。
- 事务写入：同一批补丁先检查地址、文件偏移、原字节、批内及历史范围重叠，再统一
  写入。二进制或日志落盘失败时从本次备份回滚，不会留下半套补丁。
- 不改文件大小：所有补丁均为等长替换（`PatchOp` 构造时强制校验），符合 AWDP
  「最小修改」的提交习惯（参考蚁景《AWDPwn 漏洞加固总结》的原则）。
- 支持架构：x86-64 与 i386；其余架构在请求入口直接报错，不静默降级。

## 模块清单

| 文件 | 职责 |
| --- | --- |
| `features/patch/patch_core.py` | `PatchOp` 模型、`PatchLab`（备份/应用/撤销/日志）、objdump 指令行解析、code cave 查找、`jmp rel32` 编码 |
| `features/patch/seccomp_inject.py` | BPF 过滤器生成（arch 校验 + nr 白/黑名单）、amd64/i386 安装 shellcode、入口 trampoline 组装 |
| `features/patch/recipes.py` | PLT 劫持、单调用跳过/固定返回值、read/recv/recvfrom/fgets 单点长度收紧、函数固定返回/ret、条件分支三态控制、指令区间汇编与自定义字节 |
| `features/patch/bytecode_catalog.py` | 指令↔机器码静态目录（约 60 条）、参数化编码器（nop 长度 / mov r32,imm32 / xor / rel32 计算）、objdump 原始字节反汇编 |
| `features/patch/exporters.py` | pwntools `patch.py` 脚本、字节 diff 文本、从只读原始副本回放的干净 patched ELF |

Bridge 方法（`electron_bridge.py`）：`patch_recipes / patch_audit / patch_preview / patch_apply /
patch_list / patch_undo / patch_clear / patch_reconcile / patch_export / patch_probe / patch_instructions /
patch_disasm_raw / patch_bytecode_lookup / patch_encode`。

## 手法原理

### 0. Keypatch 式汇编补丁 + IDA 联动（VNext.5）

- **汇编补丁**（手动 Patch 选中指令 → 「汇编补丁」）：输入 Intel 语法汇编，
  keystone（IDA 插件 Keypatch 同款引擎）实时编译显示机器码与长度；新指令
  短于原指令时按 Keypatch 行为自动 NOP 填充，超出则禁止（等长替换铁律）。
  相对跳转（jmp/call）按选中地址解析 rel32。keystone 为可选依赖
  （`pip install keystone-engine`），缺失时给出安装指引。
- **IDA 联动**：经本机 [IDA-CLI](https://github.com/ze-mu-zhou/IDACLI)
  （idalib，IDA Pro 9.0+，实测 9.4）驱动真实 IDA 数据库。桥进程零 import
  依赖——按需 spawn 装有 ida_cli 的 Python 3.11+（`IDA_CLI_PYTHON` 可覆盖，
  默认探测 `D:\python\python.exe` 等），驱动进程常驻复用 AgentSession。
  手动 Patch 页顶栏：「检测 IDA」状态徽章、「IDA 分析」（pwn 体检：危险
  导入/可疑符号/命中字符串/缓解提示）、「查看伪代码」（Hex-Rays 反编译）。
  已应用补丁由用户点击「同步已应用补丁到 IDA」后写入 IDA 数据库，避免后台探测阻塞导入。
  安装：
  `<IDA目录>\idalib\python\py-activate-idalib.py -d <IDA目录>` +
  `pip install -e <IDACLI 仓库>`。

### 1. seccomp 沙箱注入（沙箱通防）

思路与社区工具 retr0-Patcher / EvilPatcher 一致：

1. 按系统调用号生成经典 BPF 过滤器：`A = arch`（不匹配直接 KILL）→ `A = nr` →
   白/黑名单逐项 `JEQ` → 默认动作。黑名单模式命中即 `KILL_PROCESS`，默认
   `ALLOW`；白名单模式反之。
2. 在可执行 PT_LOAD 里找**未被任何 section 占用的全零空洞**（code cave），
   放入：安装 shellcode + 被覆盖的入口前缀指令 + 回跳 `jmp rel32` + 过滤器数据。
3. 入口（`e_entry`）按指令边界覆盖 ≥5 字节，写入 `jmp rel32` 进 cave（多余
   字节 NOP）。shellcode 先 `PR_SET_NO_NEW_PRIVS` 再 `PR_SET_SECCOMP(MODE_FILTER)`，
   过滤器指针在栈上构造 `sock_fprog{len, filter}`，全程 RIP 相对寻址
   （i386 无 RIP 相对，用 `call/pop` 取址），PIE 无关。

内置预设：① 仅禁 execve/execveat（最保守）② 追加禁 fork/vfork/clone（防反弹
shell；自 fork 的服务会被误杀）③ 白名单仅 read/write/exit（极严格，glibc 常规
程序会被杀，慎用）。自定义规则走 seccomp-tools 风格文本（`default kill` /
`allow read` / `kill execve`），复用 `core/syscalls.py` 的调用号表。

已知限制：挡不住仅用白名单内调用完成的攻击（如 ORW 读旗）；入口前缀若含
RIP 相对寻址需人工复核（`_start` 开头通常没有）。

实测教训（v0.33 真机验证踩坑记录，均已固化进实现与单测）：

1. **BPF 指令布局**：`struct sock_filter` 是 `code(u16) jt(u8) jf(u8) k(u32)`
   （`<HBBI`）。打成 `<BBHI` 会让 jt 溢入 code 高字节（如 0x0215），
   内核对 `PR_SET_SECCOMP` 直接 EINVAL，且错误字节经同格式 unpack 回读
   时"看起来正确"，极易误诊。
2. **rdx 必须保存**：入口 ABI 约定 rdx=rtld_fini，`_start` 在 trampoline
   回跳后执行 `mov r9, rdx`；shellcode 用 rdx 传 fprog 指针若不恢复，
   进程退出时 `__run_exit_handlers` 会跳进 fprog 栈地址（SIGSEGV）。
   amd64 shellcode 首尾 `push rdx / pop rdx`。
3. **段尾 cave 的页映射语义**：code cave 常落在可执行段 filesz 之外的
   页尾填充区——加载器整页映射，运行时有效；导出回放需要页对齐包含判定
   （`page_aware_vaddr_to_offset`），严格 PT_LOAD 区间会拒绝。
4. **防重复注入**：入口首字节已是 `jmp rel32` 时拒绝再次 seccomp 注入
   （避免双重 trampoline）；正常流程由补丁日志的重叠检测兜底。
5. **WSL 子进程必须 `stdin=DEVNULL`**（v0.33.1，真机排查）：`run_tool` 派生的
   wsl.exe 会继承并吞掉桥的 stdin 管道里排队的 JSON-RPC 请求行——Patch 页是
   第一个在导入期间并发发多个请求的界面，排队的 `patch_recipes` 等请求被
   吃掉后表现为永久挂起。修复覆盖 `core/wsl.py` 与 `pwndbg_manager.py`，
   回归测试断言两处都传 `subprocess.DEVNULL`。
6. **cave 不得越出可执行段**：空隙扫描的边界必须封顶在 `scan_end` 内，
   否则 R（只读不可执行）段尾的全零区会被误选为 cave，跳入即 SIGSEGV
   （32 位样本实测踩坑，已加双 LOAD 回归测试）。

### 2. 危险函数劫持（PLT / 调用点）

- **调用点改写**（V1ct0r 手法）：扫描全部函数的 `call xxx@plt` 指令（E8 rel32），
  重算 4 字节位移指向目标 PLT（如 `system → exit`）。仍是 5 字节 call，布局不变。
- **PLT stub 整体重写**：源 stub 前 5 字节改 `jmp rel32 → 目标@plt`，剩余字节
  NOP；对该函数的所有调用全局生效（含正常业务）。

### 3. read / recv / fgets 长度收紧

在选中函数内定位**紧邻 callee 调用**的 `mov $imm32,%edx`（read / recv / recvfrom
第 3 参数）或 `mov esi`（fgets 第 2 参数），把 imm32 换成安全长度。归属判定要求
mov 之后的第一条直接调用就是目标调用（允许中间 ≤4 条指令），不会把无关调用前的
立即数误改。32 位按 cdecl 参数位置从 call 向前回溯：read/recv/recvfrom 取第 3 参数、
fgets 取第 2 参数的 `push $imm`，仅接受可证明且能等长编码的 `68 imm32` / `6a imm8`。
可以填写长度立即数地址，只修同一函数内的单个调用；留空才处理全部匹配。自动扫描复用
同一套规则，寄存器与调用对不上时不生成建议。

### 4. 函数 NOP / ret 化

- 固定返回值：入口改为 `xor eax,eax; ret`、`or eax,-1; ret` 或
  `mov eax,imm32; ret`，按完整指令边界扩展并用 NOP 补齐。
- ret 化：仅首字节改 `0xC3`（1 字节最小修改），调用即返回；返回值为 eax 残留。
- 整函数 NOP：会移除 ret/尾跳转，可能贯穿到相邻代码，仅用于明确不可达的代码区。

### 5. 手动字节 Patch

选中函数 → 指令表（地址 / 原始字节 / 汇编，来自 Python 端 `patch_instructions`）
→ 选中指令 → NOP 该指令 / NOP 单个 call / 跳过 call 并令 EAX=0 / NOP 到函数尾 /
输入多行汇编或自定义 hex 写入选中地址
（`expected_size` 校验等长）。字节码查询面板的目录条目可一键填入。

当新汇编超过选区时可选「code cave 跳板」：覆盖至少 5 字节完整指令，跳到可执行段内
未被 section 占用的全零空洞，执行自定义汇编后回到选区末尾。支持替换、原指令前插入、
原指令后插入；后两种模式拒绝搬运 RIP 相对和控制流指令，避免静默生成错误重定位。
该模式适合 UAF 后清空槽位、补动态长度比较、增加状态检查等多指令修复。

### 6. 条件跳转三态控制

短跳转（70-7F）与近跳转（0F 80-8F）支持取反、强制跳转和永不跳转。近跳转改成
5 字节 `jmp rel32 + nop` 时会重算位移，保证目标地址不变；非 jcc 指令会被拒绝。
它可用于 off-by-one、负数边界、鉴权分支和错误路径修补。

## 导出格式

| 产物 | 说明 |
| --- | --- |
| `patch_<name>.py` | pwntools 脚本：`ELF(...).write(vaddr, bytes.fromhex(...))` + `save()`，附使用注释；比赛常用提交格式 |
| `<name>_patched` | 从**只读原始副本**按 vaddr 回放全部补丁（避开工作副本上 patchelf 的 interpreter/rpath 修改），回放前逐条校验原字节一致，不一致即拒绝 |
| `<name>_patch.diff` | `offset | vaddr | 原字节 | 新字节 | 说明` 的核对文本 |

## 测试

- Python：`tests/test_patch_lab.py`——手工构造最小 ELF64 fixture，
  覆盖地址换算、cave 查找、BPF/shellcode 的 golden 字节断言、trampoline 位移回算、
  recipes 数学（含 recv/recvfrom 长度归属、固定返回值与分支三态）、事务应用/整组撤销/冲突拦截、
  组合预览合并、反汇编缓存失效、三种导出、bridge RPC 层（Mock objdump）。
  运行：`python -m unittest tests.test_patch_lab`（pwncraft 目录）。
- Electron UI：`pwncraft-electron/tests/patch-ui.cjs`——真实 renderer + preload +
  IPC fixture，驱动四个 tab 的选择/预览/应用/撤销/导出、组合通防批量预览与 XSS 转义断言。
  运行：`node node_modules/electron/cli.js tests/patch-ui.cjs`。
- 真实模板验收：`tools/validate_awdp_templates.py` 会用 WSL gcc 临时编译一个真实 ELF，
  逐项应用 seccomp、PLT 调用点、PLT stub、read 长度、整函数 NOP、函数 ret、区间 NOP、
  自定义字节、NOP 单处调用、NOP 指令区间、汇编补丁、固定返回值等模板，并分别编译 amd64/i386 ELF；
  每项均检查预览不写盘、应用生效、比赛包导出、整组撤销，
  并对可执行模板核对真实运行行为。运行：`python tools/validate_awdp_templates.py`。

## 比赛闭环增强

- **导入即多阶段扫描**：`patch_audit` 检查危险调用、常量输入长度与 ELF 保护；
  `vuln_points` 在 amd64 用寄存器定义-使用链、在 i386 用 cdecl 参数回溯，覆盖
  read/recv/recvfrom/pread/readlink/fgets/fread、memcpy/memmove/mempcpy/strncpy/bcopy、
  snprintf/getcwd 等有界写入。长度支持 add/sub/imul/shl/shr/and 常量传播，calloc 使用
  `count × size`，readelf 对象符号与**段表容量**为 `.bss/.data` 提供真实边界。
- **跨函数与非溢出漏洞**：自动传播一层包装函数的缓冲区和长度参数；分析 printf/scanf 族
  固定/非固定格式串与 `%n`，追踪 system/popen/exec 族命令参数；在同一函数内识别可证明的
  非法 free、同槽位 double-free、释放后传给危险调用以及返回当前栈帧地址。

### 2023 春秋杯实测驱动的四项增强

用 `datasets/vuln_corpus/chunqiu2023.json`（3 题真值，独立动态验证）对照，修掉四类盲区：

- **函数边界恢复（`.eh_frame` FDE）**：符号被 `strip` 时 `objdump -d` 只输出一个 `<.text>`，
  于是跨函数分析全部退化成单函数、发现全归到 `.text`。现在从 `readelf --debug-dump=frames`
  的 `pc=begin..end` 切分（不手写 DWARF 解码——FDE 指针宽度由 CIE 的 augmentation `R` 决定，
  x86-64 默认是 `pcrel|sdata4` 的 4 字节而非 8）。实测 easy_LzhiFTP 恢复出 8 个函数、
  babyaul 恢复出 564 个。`coverage.functions_recovered` 报告恢复数量。
- **可写段 ≠ 固定字面量**：`.bss/.data` 里的地址只是地址固定，内容仍可被运行时写入。
  旧实现把这类地址当作「格式串不在文件映像」降级为 medium，**漏掉了真漏洞**。
  现在按段 flags 判定：可写段 + 本函数写入过该地址 → `format_string_candidate`(critical) /
  `command_injection_candidate`；仅落在可写段 → `mutable_format_slot` / `mutable_command_slot`(high)；
  只读段才判 `within_bound`。实测 easy_LzhiFTP `fgets(.bss 0x4968,8)` → `printf(同一缓冲)` 被判 critical。
- **i386 PIC 与 fortify 变体**：`lea -X(%ebx),%eax` 经 `__x86.get_pc_thunk.*` + `add $imm,%ebx`
  还原 GOT 基址后再定位目标；`__printf_chk/__fprintf_chk/__*sprintf_chk` 的格式串参数因前置
  flag 参数而后移。不处理这两点，32 位题的格式化字符串/命令面会整体退化。实测 p2048 的
  `system("/bin/sh")`（`.rodata` 固定串）不再是 high 级误报。
- **无长度参数的写循环**：新增两类不经过任何 libc 输入函数的越界写。
  `pointer_step_overflow`：`inc REG` 后写 `-K(REG)` 且循环内无 `cmp/test` 上界（p2048 的
  game 主循环）；`off_by_one_null_write`：读入长度与写入下标同源，`buf[长度]=0` 越界一字节
  （babyaul 的 `add_chunk` 0x6528，正是该题的利用点）。注意编译器会生成
  `push x; addq $8,(%rsp); ret` 跳板，它落在写入点之前，**不能**在中间 `ret` 处中断回溯。

### 第二轮：数组索引与堆可用区

- **全局数组索引越界**：`lea (,%REG,S)` + `lea BASE(%rip)` 识别带步长的数组访问，再回溯
  找到保护它的常量上界比较，产出两类结论。
  - `array_index_off_by_one`：上界立即数 ≥ 推断容量。easy_LzhiFTP 的 touch 用
    `cmp $0x10,%eax; jg` 放行 `idx==16`，而数组只有 16 个元素（0..15）→ 越界写到相邻数组。
  - `array_index_signed_bypass`：上界用**有符号**比较（`jg/jge/jl/jle`）、下标可追溯到
    `atoi/strtol/scanf` 等输入解析、且同函数内无下界检查 → 负下标绕过。
    easy_LzhiFTP 的 edit 即 `cmp $0xf; jg` + `atoi` → 负 idx 越界取指针后 `read` 写入。
  - 容量推断优先 `readelf` OBJECT 符号；无符号时用**相邻数组基址**（easy_LzhiFTP：
    0x4a80 之上最近的数组基址 0x4b00 → 0x80/8 = 16 个元素，与人工逆向一致）；
    最后退到段末尾。只用「数组基址」做边界 —— 数组中间的标量引用（`mov 0x4a98(%rip)`）
    不是边界，拿它推断会把容量算小并误报（实测曾算出 3 个元素）。
- **glibc 可用区精化**：`malloc(n)` 的可用区是 `align16(n+8)-8`，只有 `n % 16 == 8` 时
  `usable == n`，`buf[n] = 0` 才真的越界。同函数内若存在尺寸来源等同于读入长度的 `malloc`，
  常量尺寸直接按公式判定（偏小则**不报**），运行时尺寸则在结论里写明
  「当且仅当 size%16==8 时越界」。这避免了把 babyaul 的 `malloc(0x100)`（落在 usable
  0x108 内）当成漏洞。
- **objdump 注释剥离**：行尾注释（`... # 4c00 <stderr@GLIBC_2.2.5+0xb00>`）会被并进操作数，
  让 `dst_reg` 匹配失败、定义链断裂。所有操作数解析前先剥注释，注释单独保留给地址提取。

### 第三轮：三个静默失效的判据

修的都是「代码看起来对、但对真实二进制不生效」的判据错误：

- **blob 触发不能看函数名**。原判据要求最大函数的**名字以 `.` 开头**。objdump 在缺本地
  符号时会拿最近的动态符号拼出合成名 —— 2025 长城杯 minidb 得到的是
  `err@@Base-0xb6f`（占 78% 指令），不以 `.` 开头 → 整题跳过恢复，两个函数名塌成一个。
  改为按**地址跨度**判定：某个「函数」跨越 `.text` ≥50% 的空间即为 blob。
  修复后 minidb 20 → 33 个函数。
- **护栏必须引用被步进的寄存器**。「循环内无 cmp」不足以判定无界：p2048 的 `game` 主循环
  约 120 条指令，其中大量 `cmpb $0x72,-0x41d(%ebp)` 只做按键分发，与 `edi` 完全无关。
  原判据取 `inc` 前 24 条做窗口，把这些无关比较当成护栏 → 真漏洞静默消失。
  改为：循环体（回跳目标 .. 回跳点）内，只把**引用了该寄存器**（任意宽度别名）的比较
  当作护栏。修复后 p2048 报出 `pointer_step_overflow @ 0x10e3`。
- **恢复后要移除被取代的 blob**。`keep` 过滤原先只按「名字不以 `.` 开头」保留，而合成名
  `err@@Base-0xb6f` 不带 `.` 前缀 → 与原 blob 同时留下，同一个发现报两遍（minidb 每个
  `strncpy` 出现两次）。改为按**地址在 `.text` 之外**保留（.plt/.init/.fini 等桩）。
  修复后 minidb 发现数 20 → 10，无重复。

### 能力矩阵（实测）

| 题目 | 恢复函数 | critical | high | 命中的 verdict |
|---|---|---|---|---|
| 春秋杯2023 easy_LzhiFTP | 8 | 4 | 5 | `format_string_candidate`×2、`array_index_off_by_one`×2、`array_index_signed_bypass`×5 |
| 春秋杯2023 babyaul | 564 | 1 | 2 | `off_by_one_null_write`×1（带 usable 条件） |
| 春秋杯2023 p2048 | 0（无需） | 1 | 0 | `pointer_step_overflow`×1（game 主循环无界指针写） |
| 2024CISCN CHR | 12 | 0 | 3 | `use_after_free_candidate`×2、`double_free_candidate`×1 |
| 2025长城杯 minidb | 16 | 0 | 0 | 恢复生效（原 0）；该题 UAF 需堆生命周期跨函数建模 |
| 网鼎杯2024 short | 0（无需） | 1 | 1 | `overflow_confirmed`×1 |

> 「恢复函数 = 0」有两种含义：**无需恢复**（符号完整，如 p2048/short）与
> **恢复失效**（minidb 修复前）。`coverage.functions_recovered` 只报实际重建的数量，
> 调用方需结合 `coverage.functions` 判断。

评测：

```bash
python tools/vuln_corpus.py --corpus datasets/vuln_corpus/chunqiu2023.json
# 命中 7/7  漏报 0  误报 0
```

- **分级证据与修复入口**：每项返回 severity、category、confidence、调用地址、证据与修复建议。
  能证明对象容量且能由现有模板安全处理的 read/recv/recvfrom/fgets 越界，会直接显示
  「预览修复」并进入正常的预览令牌、应用、撤销流程。候选和 unknown 不会伪装成已证明漏洞。
- **组合通防（一次预览 / 一次应用）**：审计项默认全选、可按需勾选，`patch_preview` 接受
  `requests` 列表把多项缓解合并成一批补丁（同地址同字节去重，同地址不同字节明确拒绝），
  预览通过后一次 apply 写入同一批次，可在补丁管理里整组撤销。
- **补丁后存活探测**：管理页可给出固定 argv、stdin 与 1–15 秒超时，分别运行工作副本和
  只读原始副本，对比退出码与 stdout；补丁日志存在漂移或冲突时拒绝运行。
- **AWDP 比赛包**：导出 zip 内含补丁后 ELF、可重放的 `patch.py`、逐字节 `patch.diff`
  和 `manifest.json`。清单记录源文件/产物 SHA-256、补丁组数及每条补丁的地址与摘要；
  zip 先写临时文件再原子替换，避免中断留下半包。

## 来源

- retr0-Patcher（看雪《基于 pwntools 和 seccomp-tools 的 awd pwn 通防小工具》）：
  seccomp 注入通防思路与沙箱规则形态。
- Hello CTF《AWD 技巧》：PLT/GOT 替换修复、机器码对照表、通防思路。
- V1ct0r《AWD 中的 patch 技巧总结》：read 长度收紧、printf→puts 位移改写。
- [AwdPwnPatcher](https://github.com/aftern00n/AwdPwnPatcher)：原位汇编、call/jmp 跳板、
  code cave 多指令补丁与版本化管理思路；本项目额外限制完整指令边界和不安全重定位。
- [Keypatch](https://github.com/keystone-engine/keypatch)：Keystone 实时汇编和短指令 NOP 补齐交互。
- 蚁景《AWDPwn 漏洞加固总结》：最小修改、不改文件大小的加固原则。
- Linux 内核文档（Seccomp BPF）：过滤器语义与 `PR_SET_SECCOMP` 常量。
