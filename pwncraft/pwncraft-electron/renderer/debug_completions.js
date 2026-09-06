/**
 * pwndbg-mogai / gdb 中文命令目录 —— 调试终端补全与 F1 手册的数据源。
 * n = 命令名（含常用缩写别名）  cn = 中文说明  g = gdb 原生命令
 * 全部是 pwndbg-mogai fork 实际存在的命令；不造不存在的功能。
 */
(function () {
  const C = [
    // —— pwndbg 上下文 / 视图 ——
    { n: 'context', cn: '上下文总览：寄存器 / 栈 / 代码（pwndbg 主视图）' },
    { n: 'regs', cn: '只看寄存器面板' },
    { n: 'stack', cn: '查看栈上内容（telescope 栈）' },
    { n: 'args', cn: '查看当前函数参数' },
    { n: 'retaddr', cn: '查看返回地址链' },
    { n: 'telescope', cn: '逐级解引用打印指针链，用法 telescope 0xaddr' },
    { n: 'nearpc', cn: '当前 PC 附近的反汇编' },
    { n: 'disasm', cn: '反汇编，用法 disasm <符号/地址>' },
    { n: 'wind', cn: '切换 windbg 风格分屏视图' },

    // —— 执行控制 ——
    { n: 'starti', cn: '启动程序并断在第一条指令（最快拿到入口）' },
    { n: 'start', cn: '启动并断在 main' },
    { n: 'run', cn: '运行程序（gdb 原生 r）', g: true },
    { n: 'continue', cn: '继续运行（缩写 c）', g: true },
    { n: 'ni', cn: '单步跳过一条指令（nexti）' },
    { n: 'si', cn: '单步进入一条指令（stepi）' },
    { n: 'next', cn: '单步跳过一行（gdb 原生 n）', g: true },
    { n: 'step', cn: '单步进入一行（gdb 原生 s）', g: true },
    { n: 'nextcall', cn: '跳到下一个 call 指令处' },
    { n: 'finish', cn: '执行到当前函数返回' },
    { n: 'stepuntilasm', cn: '单步直到出现指定汇编（如 stepuntilasm syscall）' },

    // —— 断点 / 观察 ——
    { n: 'break', cn: '下断点，用法 break *0x401234 / break main（缩写 b）', g: true },
    { n: 'tbreak', cn: '临时断点（命中一次即删）', g: true },
    { n: 'delete', cn: '删除断点，用法 delete 1（缩写 d）', g: true },
    { n: 'info', cn: '信息查询：info breakpoints / info registers / info functions', g: true },
    { n: 'watch', cn: '观察点：值变化时断住，用法 watch *0x55555559330', g: true },
    { n: 'catch', cn: '捕获事件：catch syscall openat 断系统调用', g: true },
    { n: 'set follow-fork-mode child', cn: '跟随子进程调试（fork 程序常用）', g: true },
    { n: 'bt', cn: '查看调用栈回溯', g: true },
    { n: 'canary', cn: '显示本进程栈 Canary 值' },

    // —— 内存读写 / 搜索 ——
    { n: 'x', cn: '查看内存，用法 x/16gx 0xaddr（gdb 原生）', g: true },
    { n: 'print', cn: '求值表达式（缩写 p）', g: true },
    { n: 'set', cn: '改内存/变量，用法 set {long}0xaddr=0x41414141', g: true },
    { n: 'search', cn: '全内存搜索字符串/值/汇编，用法 search -8 0x41414141' },
    { n: 'searchmem', cn: '内存搜索（旧接口）' },

    // —— ptmalloc2 堆全家桶 ——
    { n: 'heap', cn: '堆总览：各 chunk 列表与状态' },
    { n: 'vis_heap_chunks', cn: '可视化堆块布局（ASCII 图，看 overlap 神器）' },
    { n: 'heap_config', cn: '显示 pwndbg 堆调试配置' },
    { n: 'ptmalloc2_tracking', cn: '开关 ptmalloc2 追踪（malloc/free 事件打印）' },
    { n: 'top_chunk', cn: '显示 top chunk 地址与大小' },
    { n: 'tcachebins', cn: '查看 tcache bins 链（2.26+）' },
    { n: 'fastbins', cn: '查看 fastbins 链' },
    { n: 'smallbins', cn: '查看 small bins 链' },
    { n: 'largebins', cn: '查看 large bins 链' },
    { n: 'unsorted', cn: '查看 unsorted bin 链' },
    { n: 'bins', cn: '全部 bins 一次看全' },
    { n: 'arena', cn: '查看 main arena 结构' },
    { n: 'arenas', cn: '列出所有 arena' },
    { n: 'mp', cn: '查看 mp_ 结构（tcache/最大分配等全局参数）' },
    { n: 'malloc_chunk', cn: '按 malloc_chunk 解析某地址，用法 malloc_chunk 0xaddr' },
    { n: 'find_fake_fast', cn: '找能通过 fastbin 校验的 fake chunk，用法 find_fake_fast 0xaddr' },
    { n: 'tracemalloc', cn: '追踪 malloc/free 调用记录' },
    { n: 'restore', cn: '恢复堆到记录的初始状态（配合 ptmalloc2_tracking）' },

    // —— libc / 泄露辅助 ——
    { n: 'got', cn: '查看 GOT 表及解析后的地址' },
    { n: 'plt', cn: '查看 PLT 表' },
    { n: 'libc', cn: '显示已加载 libc 的基地址与版本信息' },
    { n: 'checksec', cn: '查看本进程二进制保护（NX/PIE/Canary/RELRO）' },
    { n: 'vmmap', cn: '查看内存映射（找 libc base / heap base 必备）' },
    { n: 'procinfo', cn: '进程信息（pid/路径/命令行）' },
    { n: 'errno', cn: '查看/设置 errno' },
    { n: 'cyclic', cn: '生成去重循环串，用法 cyclic 200；配合 cyclic -l 定位溢出偏移' },
    { n: 'cyclic_find', cn: '由崩溃值反查偏移，用法 cyclic_find 0x6161616c' },
    { n: 'one_gadget', cn: '查找 one_gadget（需外部 one_gadget 工具）' },
    { n: 'spray', cn: '堆喷射辅助' },
    { n: 'elfsymbol', cn: '解析 ELF 符号，用法 elfsymbol printf' },
    { n: 'khint', cn: '显示内核相关提示' },

    // —— pwncraft 增益 ——
    { n: 'pwncraft-snapshot', cn: '采集运行时快照（pwncraft 专用：寄存器/堆/bins 一屏导出）' },
    { n: 'pwncraft-snapshot compact', cn: '采集紧凑版快照（输出更短）' },

    // —— gdb 杂项 ——
    { n: 'quit', cn: '退出 gdb', g: true },
    { n: 'layout asm', cn: '原生汇编分屏（tui）', g: true },
    { n: 'layout regs', cn: '寄存器分屏（tui）', g: true },
    { n: 'help', cn: '帮助（gdb 原生）', g: true },
    { n: 'dump binary memory', cn: '导出内存到文件，用法 dump binary memory out.bin 0xstart 0xend', g: true },
  ];

  window.PwnDbgCommands = C;
})();
