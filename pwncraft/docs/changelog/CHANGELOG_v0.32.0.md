# CHANGELOG v0.32.0 — EXP 代码补全 + 堆画布零裁字/内容来源明晰

> 日期：2026-08-29。上一版本 v0.31.0（闪退根治 + checksec 本地解析 + 堆活操作表单）。
> 本轮两件事：按用户要求上网收集社区 exp 编写实例，为 EXP 编辑器（Monaco）加代码补全；
> 修复堆画布格子文字截断与"内容像默认模板"的来源不明问题。

## 〇、堆画布：格子零裁字 + 内容来源明晰（用户实测反馈）

- **格子文字截断**（`0x5555555592a0 ~ 0x555555559…`）：违反零裁字偏好。`fitText` 改为
  **先逐级降字号让全文放下（步进 0.5px，下限 6.5px），到底仍放不下才允许省略号**；
  卡片加宽 340 → 400（地址区间在 9px 即可完整显示）。实测
  `0x5555555592a0 ~ 0x5555555592a8` 与 `…PREV_INUSE=1)` 完整显示。
- **内容来源不明**（"也不是参照 exp 来的，更像默认在那里的"）：boot 不再自动加载
  演示模板 `basic_overflow_paint` —— 画布内容只来自用户操作 / 用户 exp / 显式加载模板。
  空态显示引导卡（三个入口：用操作表单从 malloc 开始 / 回放当前 exp.py / 加载演示模板）；
  EXP 回放失败时来源徽标变为「EXP 失败」并带原因 tooltip（此前只写日志，画布停留在
  上一次内容，看起来"不像我的 exp"）；`updateOrigin` 同步 `title` 标注来源。
- shot 流程改为**显式**加载演示模板（截图来源同样明确）。

## 一、补全数据库（`renderer/exp_completions.js`，只收录真实存在的高频 API）

来源：pwntools 官方文档（tubes/intro）、anvbis/pwntools-cheatsheet 速查表、
CTF Wiki 基本 ROP 与社区 ret2libc/fmtstr 模板（知乎 / CTF All In One）。

- **全局函数 43 项**，按类别：
  - 连接/进程：`context` / `process` / `remote` / `listen` / `ssh` / `gdb.attach` / `gdb.debug`
  - Tube IO：`send` / `sendline` / `sendafter` / `sendlineafter` / `recv` / `recvline` /
    `recvuntil` / `recvn` / `recvall` / `clean` / `interactive` / `close` / `shutdown`
  - 打包/数值：`p8`–`p64` / `u32` / `u64` / `flat` / `pack` / `cyclic` / `cyclic_find`
  - 汇编：`asm` / `disasm` / `shellcraft` / `hexdump` / `unhex`
  - ELF/libc：`ELF` / `LibcSearcher`
  - ROP/SROP：`ROP` / `SigreturnFrame` / `constants`
  - 格式化字符串：`fmtstr_payload` / `FmtStr`
  - 日志：`log`
  每项带中文 `detail` + 含真实用法示例的 `documentation`（如 u64 的
  `recvuntil(b'\x7f')[-6:].ljust(8, ...)` 经典泄露写法）。
- **成员补全 8 张表**：`elf.`（sym/plt/got/search/address/section/read/libc）、`libc.`、
  `p.`/`io.`（tube 全套）、`context.`、`rop.`（call/raw/find_gadget/rdi/…/chain/dump）、
  `frame.`、`log.`——按接收者上下文给出该对象的成员，而不是全量混排。
- **exp 模板片段 9 个**（InsertAsSnippet，带可跳转占位符）：`exp`（完整骨架，含
  process/G 分支）、`ret2libc`（两阶段泄露+LibcSearcher）、`ret2text`、`shellcode`、
  `fmt`（fmtstr_payload 任意写）、`fmtleak`、`srop`（SigreturnFrame）、`ropchain`
  （ROP 类）、`u64leak`。

## 二、编辑器接线（`app.js registerExpCompletions`）

- `monaco.languages.registerCompletionItemProvider('python')`，触发字符 `.`
  与 `_`；`.` 后按接收者路由到成员表，其余场景给函数+模板（模糊匹配交给 Monaco）。
- 函数插入带 `$0` 光标落点；片段为多行 InsertAsSnippet；注册整体 try/catch，
  失败仅降级提示不影响编辑器。
- 运行时探针验证：exp 页 Monaco 模型就绪、补全数据装载 43 函数/9 片段/8 成员表。

## 三、版本

`APP_VERSION v0.32.0`、`package.json 0.32.0`、状态栏同步。
