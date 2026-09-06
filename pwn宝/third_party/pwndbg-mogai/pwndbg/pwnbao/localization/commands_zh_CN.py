from __future__ import annotations

_DESCRIPTIONS = {
    "ai": "向 AI 询问当前调试上下文",
    "arena": "显示当前线程使用的 arena",
    "arenas": "列出进程中的所有 arena",
    "argc": "显示程序参数数量",
    "argv": "显示程序参数内容",
    "aslr": "查看或切换 ASLR 状态，重启程序后生效",
    "asm": "将汇编代码组装为字节",
    "attach": "附加到指定进程或进程名",
    "auxv": "显示辅助向量",
    "bt": "显示调用栈",
    "breakrva": "按模块基址偏移设置断点",
    "checksec": "显示 ELF 安全保护",
    "context": "显示当前寄存器、反汇编、栈和调用栈",
    "disasm": "反汇编指定地址范围",
    "decomp": "反编译当前地址附近的代码",
    "decompiler-integration": "管理 Pwndbg 与反编译器的连接",
    "dev-dump-instruction": "输出指令对象的内部字段",
    "distance": "计算两个地址之间的距离或偏移",
    "down": "切换到当前调用者选择的栈帧",
    "dq": "从指定地址开始输出 qword",
    "ds": "输出指定地址处的字符串",
    "dt": "输出类型信息并可叠加内存内容",
    "dump-register-frame": "显示保存在内存中的寄存器帧",
    "entry": "显示程序入口地址",
    "eval": "计算并显示表达式",
    "gdbserver": "启动或连接 GDB 远程调试服务",
    "got": "显示 GOT 表",
    "hexdump": "以十六进制显示内存",
    "info": "显示调试器信息",
    "jmpcall": "查找跳转和调用指令",
    "kill": "终止当前调试进程",
    "log": "记录或查看调试输出",
    "maps": "显示进程内存映射",
    "memfrob": "对内存执行 memfrob 变换",
    "nearpc": "显示当前指令附近的反汇编",
    "next": "单步执行并越过函数调用",
    "nextcall": "执行到下一次函数调用",
    "nextret": "执行到当前函数返回",
    "pattern": "生成或查找循环模式",
    "procinfo": "显示当前进程信息",
    "regs": "显示寄存器",
    "rop": "搜索 ROP gadgets",
    "run": "启动或重新启动程序",
    "search": "在当前进程内存中搜索",
    "stack": "显示栈内容",
    "telescope": "从指定地址开始递归解引用",
    "vmmap": "显示进程内存映射",
    "heap": "显示 glibc Heap Chunk",
    "bins": "显示所有 glibc bins",
    "tcachebins": "显示 tcache bins",
    "fastbins": "显示 fastbins",
    "vis-heap-chunks": "显示物理 Heap Chunk 分布",
    "plt": "显示 PLT 表",
    "cyclic": "生成 cyclic pattern",
    "cyclic-find": "查找 cyclic pattern 偏移",
    "retaddr": "查找栈上的返回地址",
    "canary": "显示 stack canary",
    "frame-explain": "基于 GDB unwinder/CFI 解释当前 frame",
    "return-info": "显示 unwinder 确认的返回目标",
    "rbp-info": "判定 RBP 是帧指针还是通用寄存器",
    "stackof": "定位一个栈地址所属的 frame",
    "safe-link": "使用字段地址计算 Safe-Linking encode/decode",
}

_SEARCH_TERMS = {
    "栈": ("stack", "telescope", "frame", "backtrace", "retaddr", "stackof"),
    "堆": ("heap", "bins", "tcachebins", "fastbins", "vis-heap-chunks"),
    "内存映射": ("vmmap",),
    "内存": ("vmmap", "search", "hexdump", "telescope"),
    "寄存器": ("context", "regs", "rbp-info"),
    "返回": ("return-info", "retaddr"),
}


def command_description(name: str, fallback: str = "") -> str:
    key = str(name).strip()
    translated = _DESCRIPTIONS.get(key)
    if translated:
        return translated
    # Keep every live command discoverable even when upstream adds a command
    # before a dedicated translation lands.  The English command name remains
    # visible in the slash title, while the description stays readable Chinese.
    return f"{key}：Pwndbg 原生命令，参数和输出保持原生格式"


def chinese_matches(query: str) -> tuple[str, ...]:
    needle = str(query).strip().casefold()
    result: list[str] = []
    for term, names in _SEARCH_TERMS.items():
        if needle in term.casefold() or term.casefold() in needle:
            result.extend(names)
    for name, description in _DESCRIPTIONS.items():
        if needle and needle in description.casefold():
            result.append(name)
    return tuple(dict.fromkeys(result))


def search_keywords(name: str) -> tuple[str, ...]:
    return tuple(term for term, names in _SEARCH_TERMS.items() if name in names)
