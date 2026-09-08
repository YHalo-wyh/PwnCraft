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
| `features/patch/recipes.py` | PLT 劫持（调用点 rel32 重算 / stub 整体重写）、read/fgets 长度收紧、函数 NOP / ret 化、自定义字节、`RECIPE_CATALOG` 使用说明 |
| `features/patch/bytecode_catalog.py` | 指令↔机器码静态目录（约 60 条）、参数化编码器（nop 长度 / mov r32,imm32 / xor / rel32 计算）、objdump 原始字节反汇编 |
| `features/patch/exporters.py` | pwntools `patch.py` 脚本、字节 diff 文本、从只读原始副本回放的干净 patched ELF |

Bridge 方法（`electron_bridge.py`）：`patch_recipes / patch_preview / patch_apply /
patch_list / patch_undo / patch_clear / patch_reconcile / patch_export / patch_instructions /
patch_disasm_raw / patch_bytecode_lookup / patch_encode`。

## 手法原理

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

### 2. 危险函数劫持（PLT / 调用点）

- **调用点改写**（V1ct0r 手法）：扫描全部函数的 `call xxx@plt` 指令（E8 rel32），
  重算 4 字节位移指向目标 PLT（如 `system → exit`）。仍是 5 字节 call，布局不变。
- **PLT stub 整体重写**：源 stub 前 5 字节改 `jmp rel32 → 目标@plt`，剩余字节
  NOP；对该函数的所有调用全局生效（含正常业务）。

### 3. read / fgets 长度收紧

在选中函数内定位**紧邻 callee 调用**（允许中间 ≤4 条指令）的
`mov $imm32,%edx`（read）或 `mov esi`（fgets），把 imm32 换成安全长度。
仅支持 64 位（寄存器传参）；32 位走 `push $imm` 栈传参，无稳定模式，提示用
手动字节 patch 处理。

### 4. 函数 NOP / ret 化

- 整函数 NOP：按反汇编指令边界把函数体全填 `0x90`。
- ret 化：仅首字节改 `0xC3`（1 字节最小修改），调用即返回；返回值为 eax 残留。

### 5. 手动字节 Patch

选中函数 → 指令表（地址 / 原始字节 / 汇编，来自 Python 端 `patch_instructions`）
→ 选中指令 → NOP 该指令 / NOP 到函数尾 / 输入自定义 hex 写入选中地址
（`expected_size` 校验等长）。字节码查询面板的目录条目可一键填入。

## 导出格式

| 产物 | 说明 |
| --- | --- |
| `patch_<name>.py` | pwntools 脚本：`ELF(...).write(vaddr, bytes.fromhex(...))` + `save()`，附使用注释；比赛常用提交格式 |
| `<name>_patched` | 从**只读原始副本**按 vaddr 回放全部补丁（避开工作副本上 patchelf 的 interpreter/rpath 修改），回放前逐条校验原字节一致，不一致即拒绝 |
| `<name>_patch.diff` | `offset | vaddr | 原字节 | 新字节 | 说明` 的核对文本 |

## 测试

- Python：`tests/test_patch_lab.py`（43 项）——手工构造最小 ELF64 fixture，
  覆盖地址换算、cave 查找、BPF/shellcode 的 golden 字节断言、trampoline 位移回算、
  recipes 数学、事务应用/整组撤销/冲突拦截、三种导出、bridge RPC 层（Mock objdump）。
  运行：`python -m unittest tests.test_patch_lab`（pwncraft 目录）。
- Electron UI：`pwncraft-electron/tests/patch-ui.cjs`——真实 renderer + preload +
  IPC fixture，驱动四个 tab 的选择/预览/应用/撤销/导出与 XSS 转义断言。
  运行：`node node_modules/electron/cli.js tests/patch-ui.cjs`。
- 真实模板验收：`tools/validate_awdp_templates.py` 会用 WSL gcc 临时编译一个真实 ELF，
  逐项应用 seccomp、PLT 调用点、PLT stub、read 长度、整函数 NOP、函数 ret、区间 NOP、
  自定义字节共 8 种模板；每项均检查预览不写盘、应用生效、干净 ELF 导出、整组撤销，
  并对可执行模板核对真实运行行为。运行：`python tools/validate_awdp_templates.py`。

## 来源

- retr0-Patcher（看雪《基于 pwntools 和 seccomp-tools 的 awd pwn 通防小工具》）：
  seccomp 注入通防思路与沙箱规则形态。
- Hello CTF《AWD 技巧》：PLT/GOT 替换修复、机器码对照表、通防思路。
- V1ct0r《AWD 中的 patch 技巧总结》：read 长度收紧、printf→puts 位移改写。
- 蚁景《AWDPwn 漏洞加固总结》：最小修改、不改文件大小的加固原则。
- Linux 内核文档（Seccomp BPF）：过滤器语义与 `PR_SET_SECCOMP` 常量。
