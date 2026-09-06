from __future__ import annotations

_SECTIONS = {
    "registers": "寄存器 REGISTERS",
    "disasm": "反汇编 DISASM",
    "stack": "栈 STACK",
    "backtrace": "调用栈 BACKTRACE",
    "arguments": "当前参数 ARGUMENTS",
    "expressions": "表达式 EXPRESSIONS",
    "heap tracker": "堆跟踪 HEAP TRACKER",
    "last signal": "停止信号 LAST SIGNAL",
    "source (code)": "源码 SOURCE (CODE)",
    "decomp": "伪代码 DECOMP",
}

# Kept as migration vocabulary for saved screenshots and old rule fixtures;
# these English suffixes are no longer rendered in the compact UI.
_LEGACY_LABELS = ("寄存器 REGISTERS", "反汇编 DISASM", "栈 STACK", "调用栈 BACKTRACE")


def section_title(title: str) -> str:
    text = str(title or "")
    key = text.casefold()
    if key.startswith("threads ("):
        return "线程 " + text[len("threads ") :]
    return _SECTIONS.get(key, text)
