"""漏洞点确认 v3：面向 AWDP 的多阶段二进制数据流扫描。

方法吸收自 intelpwn（guaidao2/intelpwn）的语义层 v2：从调用点**反向沿
定义链回溯**（`mov dst,src` 切换追踪目标），call/jmp/ret 截断、算术污染
判未知——破除固定窗口，编译器重排/长链不漏。本项目差异：AT&T 文本
（objdump）而非 capstone Intel；结论分五档诚实输出，绝不猜测。

检测面（v3）：有界输入/复制的长度与栈、堆、全局对象容量；简单常量算术；
一层包装函数参数传播；scanf/printf 族固定与非固定格式串；命令执行参数来源；
double-free、调用型 use-after-free、栈地址返回。所有结论附带类别、置信度和证据。
"""
from __future__ import annotations

from pathlib import Path

import re

from pwncraft.features.patch.patch_core import parse_instruction_lines

# 参数序号均为 0 起；amd64 SysV 寄存器和 i386 cdecl 共用同一份语义表。
_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_BOUNDED_SPECS = {
    "read": (1, 2), "recv": (1, 2), "recvfrom": (1, 2),
    "pread": (1, 2), "pread64": (1, 2), "readlink": (1, 2),
    "readlinkat": (2, 3), "fgets": (0, 1),
    "memcpy": (0, 2), "memmove": (0, 2), "mempcpy": (0, 2),
    "strncpy": (0, 2), "bcopy": (1, 2), "memset": (0, 2),
    "explicit_bzero": (0, 1), "snprintf": (0, 1), "vsnprintf": (0, 1),
    "getcwd": (0, 1), "fread": (0, 1), "fread_unlocked": (0, 1),
}
_PRODUCT_LENGTH_ARGS = {"fread": (1, 2), "fread_unlocked": (1, 2)}
_LENGTH_REG = {name: _ARG_REGS[length] for name, (_, length) in _BOUNDED_SPECS.items()
               if length < len(_ARG_REGS)}
_DEST_REG = {name: _ARG_REGS[dest] for name, (dest, _) in _BOUNDED_SPECS.items()
             if dest < len(_ARG_REGS)}
_DEST_REG.update({name: "rdi" for name in
                  ("gets", "strcpy", "stpcpy", "strcat", "sprintf", "vsprintf")})
_UNBOUNDED = {"gets"}
_UNBOUNDED_WRITE = {"strcpy", "stpcpy", "strcat", "sprintf", "vsprintf"}
_ALLOC_SPECS = {"malloc": (0,), "calloc": (0, 1), "realloc": (1,),
                "mmap": (1,), "mmap64": (1,)}
_ALLOC_SIZE_REG = {name: _ARG_REGS[indexes[0]] for name, indexes in _ALLOC_SPECS.items()}
_I386_LENGTH_ARG = {name: length for name, (_, length) in _BOUNDED_SPECS.items()}
_I386_DEST_ARG = {name: dest for name, (dest, _) in _BOUNDED_SPECS.items()}
_I386_DEST_ARG.update({name: 0 for name in _UNBOUNDED | _UNBOUNDED_WRITE})

_FORMAT_SPECS = {
    "printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1,
    "dprintf": 1, "sprintf": 1, "vsprintf": 1, "snprintf": 2,
    "vsnprintf": 2, "syslog": 1,
    # fortify 变体：_FORTIFY_SOURCE 下 gcc 会把 printf 族换成 __*_chk，
    # 格式串因此后移（__printf_chk(flag, fmt, ...)）。ARM/86 gcc 实测常见，
    # 漏掉这些符号会让整个格式化字符串面静默消失。
    "__printf_chk": 1, "__fprintf_chk": 2, "__dprintf_chk": 2,
    "__sprintf_chk": 3, "__snprintf_chk": 4, "__vprintf_chk": 1,
    "__vfprintf_chk": 2, "__vsprintf_chk": 3, "__vsnprintf_chk": 4,
}
_I386_FORMAT_ARG = dict(_FORMAT_SPECS)   # gcc 的 _chk flag 参数在两种 ABI 下都是前置位
_SCANF_SPECS = {"scanf": (0, 1), "fscanf": (1, 2), "sscanf": (1, 2)}
_I386_SCANF_SPECS = dict(_SCANF_SPECS)
_COMMAND_SPECS = {"system": 0, "popen": 0, "execl": 0, "execlp": 0,
                  "execle": 0, "execv": 0, "execvp": 0, "execve": 0,
                  "execvpe": 0, "wordexp": 0}
_POINTER_USE_ARGS = {
    "strlen": (0,), "puts": (0,), "free": (0,), "realloc": (0,),
    "read": (1,), "recv": (1,), "recvfrom": (1,), "fgets": (0,),
    "memcpy": (0, 1), "memmove": (0, 1), "strcpy": (0, 1),
    "strcat": (0, 1), "printf": (0,),
}
# CTF 题常把 allocator 藏在随题附带的 .so 中。仅根据导出名把这些
# wrapper 还原为 malloc/free 语义，便可让已有的尺寸、生命周期和画布
# 逻辑继续工作；它不把实现内部正确性假定为已验证。
_CUSTOM_ALLOC_ALIASES = {
    "pmalloc": "malloc", "p_malloc": "malloc",
    "safe_malloc": "malloc", "safemalloc": "malloc",
    "pool_alloc": "malloc", "pool_malloc": "malloc",
    "pfree": "free", "p_free": "free",
    "safe_free": "free", "safefree": "free", "pool_free": "free",
}

_LEA_RIP = re.compile(r"^lea\s+(?:-?0x[0-9a-fA-F]+)?\(%rip\),%(\w+)")
_LEA_RBP = re.compile(r"^lea\s+(-0x[0-9a-fA-F]+)\(%[er]bp\),%(\w+)$")
_LEA_EBX = re.compile(r"^lea\s+(-?0x[0-9a-fA-F]+)\(%ebx\),%(\w+)$")
_MOV_REG_REG = re.compile(r"^mov\s+%(\w+),%(\w+)$")
_CALL_PLT = re.compile(r"^call[qw]?\s+[0-9a-fA-F]+\s+<([^>]+)>")
_CANARY_READ = re.compile(r"^mov\s+%fs:0x28,")
_STACK_MEM = re.compile(r"(-?0x[0-9a-fA-F]+)\(%[er]bp\)")
_RIP_LOAD = re.compile(r"-?0x[0-9a-fA-F]+\(%rip\)")
_GET_PC_THUNK = re.compile(
    r"^call\s+[0-9a-fA-F]+\s+<__x86\.get_pc_thunk\.(?:bx|cx|dx|si|di)>$")
_ADD_EBX = re.compile(r"^add\s+\$(0x[0-9a-fA-F]+|[0-9]+),%ebx$")
# 直接写全局：`movl $0x1,0x33b3(%rip) # 4960` / `mov %eax,0x2c(%rip) # 40e8`
_STORE_RIP = re.compile(r"^mov[a-z]*\s+[^,]+,(?:-?0x[0-9a-fA-F]+)?\(%rip\)")

# --- 全局数组索引 ----------------------------------------------------------
_RIP_COMMENT = re.compile(r"#\s*([0-9a-fA-F]+)")
_INDEX_SCALE = re.compile(r"^lea\s+(?:0x[0-9a-fA-F]+)?\(,%(\w+),([1248])\),%(\w+)$")
_ARRAY_BASE = re.compile(r"^lea\s+-?0x[0-9a-fA-F]+\(%rip\),%(\w+)\b")
_CMP_IMM_REG = re.compile(r"^cmp[lqw]?\s+\$(0x[0-9a-fA-F]+|[0-9]+),%(\w+)$")
_CMP_IMM_SLOT = re.compile(
    r"^cmp[lqw]?\s+\$(0x[0-9a-fA-F]+|[0-9]+),(-?0x[0-9a-fA-F]+)\(%[er]bp\)$")
_CMP_ZERO = re.compile(r"^cmp[lqw]?\s+\$0x0,(?:%(\w+)|-?0x[0-9a-fA-F]+\(%[er]bp\))$")
_TEST_SELF = re.compile(r"^test[lqw]?\s+%(\w+),%(\w+)$")
_COND_JUMP = re.compile(
    r"^(j(?:a|ae|b|be|g|ge|l|le|e|ne|z|nz|s|ns|o|no|p|np|c|nc))\s")
_SIGNED_JUMPS = {"jg", "jge", "jl", "jle"}
_INPUT_PARSE_CALLS = {
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "scanf", "__isoc99_scanf", "sscanf", "__isoc99_sscanf",
    "fscanf", "__isoc99_fscanf",
}

# --- ELF 段真值 ------------------------------------------------------------
# 可写段（.bss/.data/.got）里的“地址常量”只是地址固定，**内容**仍可被运行时写入
# 改写；把这种地址当成固定字面量是危险的漏报来源（实测 2023 春秋杯
# easy_LzhiFTP：fgets(.bss) → printf(同一 .bss) 被判 unknown_format）。
SHF_WRITE = 0x1
_SECTION_CACHE: dict[tuple, list[dict]] = {}

BACKTRACK_LIMIT = 400
_ARITH = ("add", "sub", "xor", "imul", "and", "or", "shl", "shr", "inc", "dec",
          "lea", "mul", "div", "idiv", "neg", "not")


def _norm(reg: str) -> str:
    """跨宽度寄存器归一：eax/ax/al → rax，r8d → r8。"""
    reg = reg.lower().strip()
    if len(reg) == 3 and reg[0] == "e":
        return "r" + reg[1:]
    if len(reg) == 2 and reg[1] in "xhl" and reg[0] in "abcd":
        return "r" + reg[0] + "x"
    if len(reg) >= 3 and reg[-1] == "d" and reg[:-1].rstrip("0123456789") == "r":
        return reg[:-1]
    return reg


def _elf_sections(binary_path) -> list[dict]:
    """可写性判定所需的段表：`[{name, addr, size, flags}]`。

    `elf_geometry()` 的段名是 .shstrtab 内的字节偏移（未解析），这里用
    e_shstrndx 还原成可读名字，便于证据里直接写 `.bss` 而不是编号。
    结果按 (路径, mtime, 大小) 记忆化，文件被改写后自动失效。
    """
    if binary_path is None:
        return []
    path = Path(binary_path)
    try:
        stat = path.stat()
        data = path.read_bytes()
    except OSError:
        return []
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    cached = _SECTION_CACHE.get(key)
    if cached is not None:
        return cached

    from pwncraft.core.workbench import elf_geometry
    try:
        geometry = elf_geometry(path)
    except (ValueError, OSError):
        return []
    raw = list(geometry.get("sections") or [])
    is64 = bool(geometry.get("is64"))
    endian = str(geometry.get("endian") or "little")
    shstrndx = int.from_bytes(data[0x3E:0x40] if is64 else data[0x32:0x34], endian)
    base = 0
    if 0 <= shstrndx < len(raw) and int(raw[shstrndx].get("type") or 0) == 3:
        base = int(raw[shstrndx].get("offset") or 0)

    sections: list[dict] = []
    for item in raw:
        name = ""
        if base:
            start = base + int(item.get("name") or 0)
            if 0 <= start < len(data):
                stop = data.find(b"\x00", start)
                if stop > start:
                    name = data[start:stop].decode("utf-8", "replace")
        sections.append({"name": name, "addr": int(item.get("addr") or 0),
                         "size": int(item.get("size") or 0),
                         "flags": int(item.get("flags") or 0)})
    _SECTION_CACHE.clear()          # 只保留当前目标，避免多题批量扫描时无界增长
    _SECTION_CACHE[key] = sections
    return sections


def _section_at(binary_path, address) -> dict | None:
    if not address:
        return None
    for section in _elf_sections(binary_path):
        start, size = section["addr"], section["size"]
        if size and start <= int(address) < start + size:
            return section
    return None


def _writable_global(binary_path, address) -> dict | None:
    """地址落在可写段时返回该段，否则 None（只读段/未映射）。"""
    section = _section_at(binary_path, address)
    if section and (section["flags"] & SHF_WRITE):
        return section
    return None


def _i386_got_base(lines: list[dict]) -> int | None:
    """i386 PIC 的 GOT 基址：`call __x86.get_pc_thunk.bx` + `add $imm,%ebx`。

    thunk 把返回地址（下一条指令的地址）弹进 ebx，随后 add 得到 GOT 基址；
    `lea -0x1d00(%ebx),%eax` 这类取值只有算出 ebx 才能定位到 .rodata/.bss。
    """
    for index, insn in enumerate(lines):
        if not _GET_PC_THUNK.match(str(insn.get("text") or "")):
            continue
        if index + 1 >= len(lines):
            continue
        follow = lines[index + 1]
        match = _ADD_EBX.match(str(follow.get("text") or ""))
        if match:
            return (int(follow["address"]) + int(match[1], 0)) & 0xFFFFFFFF
    return None


def _written_globals(lines: list[dict], bits: int,
                     got_base: int | None = None) -> set[int]:
    """本函数内被写过的全局地址：有界输入的 dest，以及 rip/ebx 相对直接写。

    这是“可写段地址”从『需复核』升级为『数据流候选』的证据来源——只有证明
    该地址真的被写过，才敢说格式串/命令参数不是固定值。
    """
    written: set[int] = set()
    for index, insn in enumerate(lines):
        text = str(insn.get("text") or "")
        call = _CALL_PLT.match(text)
        if call:
            callee = canonical_callee(call[1])
            if bits == 32:
                dest_index = _I386_DEST_ARG.get(callee)
                if dest_index is None:
                    continue
                chain = _arg_chain(lines, index, dest_index, bits,
                                   got_base=got_base)
            else:
                dest_reg = _DEST_REG.get(callee)      # 这里是寄存器名，不是序号
                if dest_reg is None:
                    continue
                chain = _backtrack(lines, index, dest_reg, limit=BACKTRACK_LIMIT)
            if chain.get("kind") == "rip" and chain.get("address"):
                written.add(int(chain["address"]))
            continue
        if _STORE_RIP.match(text):
            comment = re.search(r"#\s*([0-9a-fA-F]+)", text)
            if comment:
                written.add(int(comment[1], 16))
    return written


def _mov_operands(text: str):
    """`mov $0x200,%edx` → ('$0x200', '%edx')；非双操作数 mov → None。"""
    parts = text.split(None, 1)
    if len(parts) != 2 or "," not in parts[1]:
        return None
    dst, _, src = parts[1].partition(",")
    return dst.strip(), src.strip()


def _dst_reg(text: str) -> str:
    """AT&T 目的操作数在逗号后：`add $0x8,%rax` → rax。"""
    parts = text.split(None, 1)
    if len(parts) != 2:
        return ""
    ops = parts[1]
    dst = ops.split(",")[-1] if "," in ops else ops
    return _norm(dst.strip().lstrip("%"))


def _fmt_arg_index(callee: str, bits: int) -> int:
    table = _I386_FORMAT_ARG if bits == 32 else _FORMAT_SPECS
    return int(table.get(callee, _FORMAT_SPECS.get(callee, 0)))


def canonical_callee(symbol: str) -> str:
    """把编译器/glibc 的内部别名归一到公开名。

    要剥的前缀：
      * `_IO_` / `__isoc99_` —— 老的 libc 内部名（如 `_IO_gets`、`__isoc99_scanf`）。
      * `__libc_` —— **静态链接**的 glibc 把 `read`/`write`/`open` 等导出成
        `__libc_read` 等别名。不剥掉的话整个静态题的输入面全部失明
        （实测 03_栈溢出/pwn_049：`read(0,ebp-0x12,0x64)` 因符号名是
        `__libc_read` 而完全未被识别）。
      * `__GI_` —— `-O2` + hidden visibility 下的内部别名（`__GI_memcpy` 等）。

    剥完后再去掉 `@@GLIBC_x.y` 版本后缀与 `+0xNN` 偏移。
    """
    raw_name = str(symbol or "").strip()
    # objdump 会把 stripped ELF 的本地函数标为最近 PLT 符号加偏移，
    # 例如 `pFree@plt+0x25e`。这不是导入的 pFree，绝不能把它混同为
    # allocator free；只接受裸符号或精确 PLT stub。
    has_symbol_offset = "+" in raw_name
    name = raw_name.split("@", 1)[0].split("+", 1)[0].strip()
    for prefix in ("__GI_", "__libc_", "_IO_", "__isoc99_"):
        if name.startswith(prefix) and len(name) > len(prefix):
            name = name[len(prefix):]
            break
    if not has_symbol_offset:
        return _CUSTOM_ALLOC_ALIASES.get(name.casefold(), name)
    return name


def _canary_offset(lines: list[dict]) -> int | None:
    """帧内 canary 槽：`mov %fs:0x28,%rX` 后紧跟 `mov %rX,-N(%rbp)`。"""
    for index, insn in enumerate(lines):
        if _CANARY_READ.match(insn["text"] or ""):
            src = (insn["text"] or "").split(",")[-1].strip().lstrip("%")
            for follow in lines[index + 1:index + 3]:
                m = re.match(rf"^mov\s+%{re.escape(src)},-?(0x[0-9a-fA-F]+)\(%rbp\)$",
                             follow["text"] or "")
                if m:
                    return int(m[1], 16)
    return None


def _split_ops(text: str) -> tuple[str, str]:
    if "," not in text:
        return "", ""
    head, _, tail = text.partition(",")
    return head.strip(), tail.strip()


def _parse_imm(operand: str) -> int | None:
    if not re.fullmatch(r"\$-?(?:0x[0-9a-fA-F]+|[0-9]+)", operand):
        return None
    return int(operand[1:], 0)


def _apply_transforms(value: int, transforms: list[tuple[str, int]]) -> int:
    """Apply operations collected newest-first while walking definitions backward."""
    result = int(value)
    for operation, operand in reversed(transforms):
        if operation == "add":
            result += operand
        elif operation == "sub":
            result -= operand
        elif operation == "imul":
            result *= operand
        elif operation == "shl":
            result <<= operand
        elif operation == "shr":
            result >>= operand
        elif operation == "and":
            result &= operand
    return result & 0xFFFFFFFFFFFFFFFF


def _backtrack(lines: list[dict], call_index: int, reg: str, *,
               limit: int = BACKTRACK_LIMIT, got_base: int | None = None) -> dict:
    """反向定义链：追 reg 的最终定义。

    返回 {'kind': 'stack'|'imm'|'alloc'|'rip'|'unknown', ...}；
    call/jmp/ret 截断（跨块不猜），算术污染 → unknown。
    """
    target = _norm(reg)
    transforms: list[tuple[str, int]] = []
    start = max(0, call_index - limit)
    for k in range(call_index - 1, start - 1, -1):
        insn = lines[k]
        raw = insn["text"] or ""
        # 剥掉 objdump 的行尾注释（`... # 4c00 <stderr@GLIBC_2.2.5+0xb00>`）。
        # 不剥会让操作数解析把注释并进目的操作数（`%eax # 4c00 <...>`），
        # `dst_reg == target` 永远不成立，定义链在此断裂——实测这会让
        # easy_LzhiFTP 的 `mov 0x33bf(%rip),%eax # 4c00` 无法识别为数组下标。
        text = raw.split("#", 1)[0].rstrip()
        call = _CALL_PLT.match(text)
        if call:
            name = call[1].split("@")[0]
            if target == "rax" and name in _ALLOC_SIZE_REG:
                return {"kind": "alloc", "alloc_insn": k, "callee": name}
            return {"kind": "unknown", "reason": f"被 call {name} 截断"}
        if text.startswith(("jmp ", "ret")):
            return {"kind": "unknown", "reason": f"被 {text.split()[0]} 截断"}
        m_lea = _LEA_RBP.match(text)
        if m_lea and _norm(m_lea[2]) == target:
            return {"kind": "stack", "offset": abs(int(m_lea[1], 16)),
                    "insn": f"0x{insn['address']:x}"}
        m_rip = _LEA_RIP.match(text)
        if m_rip and _norm(m_rip[1]) == target:
            comment = _RIP_COMMENT.search(raw)
            return {"kind": "rip", "insn": f"0x{insn['address']:x}",
                    "address": int(comment[1], 16) if comment else None}
        # i386 PIC：lea -0x1d00(%ebx),%eax —— ebx=GOT 基址，减去立即数得目标。
        # 不处理这条会让 32 位题的命令/格式串参数全部退化成 unknown（实测 p2048
        # 的 system("/bin/sh") 因此被误报为 high 级命令注入候选）。
        m_ebx = _LEA_EBX.match(text)
        if m_ebx and _norm(m_ebx[2]) == target:
            base = got_base if got_base is not None else None
            if base is None:
                base = _i386_got_base(lines)
            if base is None:
                return {"kind": "unknown", "reason": "ebx 相对取址但未找到 get_pc_thunk"}
            address = (base + int(m_ebx[1], 16)) & 0xFFFFFFFF
            return {"kind": "rip", "insn": f"0x{insn['address']:x}",
                    "address": address, "pic": "ebx"}
        zero = re.match(r"^xor[lq]?\s+%(\w+),%(\w+)$", text)
        if zero and _norm(zero[1]) == target and _norm(zero[2]) == target:
            return {"kind": "imm", "value": _apply_transforms(0, transforms),
                    "insn": f"0x{insn['address']:x}", "derived": bool(transforms)}
        if text.startswith("mov") and not text.startswith("movs"):
            ops = _mov_operands(text)
            if ops is None:
                continue
            src_op, dst_op = ops          # AT&T：第一操作数=源，第二=目的
            if dst_op.startswith("$") or not dst_op.startswith("%"):
                continue                   # 目的是内存/段寄存器 → 链断
            dst_reg = _norm(dst_op.lstrip("%"))
            if src_op.startswith("$"):
                value = _parse_imm(src_op)
                if value is not None and dst_reg == target:
                    return {"kind": "imm", "value": _apply_transforms(value, transforms),
                            "insn": f"0x{insn['address']:x}",
                            "derived": bool(transforms)}
                continue
            src_reg = src_op.lstrip("%").split(",")[0]
            if dst_reg == target:
                if re.fullmatch(r"[a-z][a-z0-9]{1,4}", src_reg):
                    target = _norm(src_reg)   # mov dst,src → 沿源继续追
                    continue
                stack = _STACK_MEM.fullmatch(src_op)
                if stack:
                    return {"kind": "slot", "offset": abs(int(stack[1], 16)),
                            "insn": f"0x{insn['address']:x}"}
                # rip 相对**加载**（如 `mov 0x33e4(%rip),%eax # 4c00`）：
                # 值是全局地址处的内容。身份仍按地址归一，便于把「读计数器」
                # 与「用计数器做数组下标」认成同一个值。
                if _RIP_LOAD.fullmatch(src_op):
                    comment = _RIP_COMMENT.search(raw)
                    return {"kind": "rip", "load": True,
                            "insn": f"0x{insn['address']:x}",
                            "address": int(comment[1], 16) if comment else None}
                return {"kind": "mem", "reason": f"来源为内存 {src_op}"}
            continue
        for op in ("add", "sub", "imul", "shl", "shr", "and"):
            if text.startswith(op + " ") or text.startswith(op + "l ") \
                    or text.startswith(op + "q "):
                if _dst_reg(text) == target:
                    operands = text.split(None, 1)[1].split(",")
                    immediate = _parse_imm(operands[0].strip())
                    if immediate is None:
                        return {"kind": "unknown", "reason": f"{op} 使用非常量"}
                    transforms.append((op, immediate))
                break
        else:
            for op in _ARITH:
                if text.startswith(op + " ") or text.startswith(op + "l ") \
                        or text.startswith(op + "q "):
                    if _dst_reg(text) == target:
                        return {"kind": "unknown", "reason": f"{op} 污染"}
                    break
    if not transforms and target in _ARG_REGS:
        return {"kind": "param", "index": _ARG_REGS.index(target),
                "reg": target, "reason": f"函数参数 {_ARG_REGS.index(target) + 1}"}
    return {"kind": "unknown", "reason": "窗口起点仍未定"}


def _arg_chain(lines: list[dict], index: int, arg_index: int, bits: int = 64,
               got_base: int | None = None) -> dict:
    if bits == 64:
        if arg_index >= len(_ARG_REGS):
            return {"kind": "unknown", "reason": "参数超出寄存器传参范围"}
        return _backtrack(lines, index, _ARG_REGS[arg_index], got_base=got_base)
    pushes = _cdecl_pushes(lines, index)
    if len(pushes) <= arg_index:
        return {"kind": "unknown", "reason": "cdecl 参数不可解析"}
    pos, operand = pushes[arg_index]
    immediate = _parse_imm(operand)
    if immediate is not None:
        return {"kind": "imm", "value": immediate, "insn": f"0x{lines[pos]['address']:x}"}
    if operand.startswith("%"):
        return _backtrack(lines, pos, operand[1:], got_base=got_base)
    return {"kind": "unknown", "reason": f"cdecl 参数来源 {operand}"}


def _object_for(address: int | None, objects: list[dict] | None) -> dict | None:
    if address is None:
        return None
    for item in objects or ():
        start, size = int(item.get("address") or 0), int(item.get("size") or 0)
        if size > 0 and start <= address < start + size:
            return {"name": str(item.get("name") or "global"),
                    "address": start, "size": size - (address - start)}
    return None


def _allocation_size(lines: list[dict], call_index: int, callee: str,
                     bits: int = 64) -> tuple[int | None, str]:
    values: list[int] = []
    evidence: list[str] = []
    for arg_index in _ALLOC_SPECS.get(callee, ()):
        chain = _arg_chain(lines, call_index, arg_index, bits)
        if chain.get("kind") != "imm":
            return None, f"{callee} 分配尺寸非常量"
        values.append(int(chain["value"]))
        evidence.append(str(chain.get("insn") or ""))
    if not values:
        return None, f"{callee} 分配尺寸不可解析"
    size = values[0] * values[1] if callee == "calloc" and len(values) == 2 else values[-1]
    return size, f"{callee} 尺寸 {size:#x} @ {' / '.join(filter(None, evidence))}"


def _resolve_dest(lines: list[dict], chain: dict, *, objects: list[dict] | None,
                  bits: int = 64, binary_path=None) -> tuple[dict | None, str]:
    if chain.get("kind") == "stack":
        return ({"kind": "stack", "offset": chain["offset"]},
                f"栈槽 {'e' if bits == 32 else 'r'}bp-{chain['offset']:#x} @ {chain.get('insn')}")
    if chain.get("kind") == "alloc":
        size, evidence = _allocation_size(lines, int(chain["alloc_insn"]),
                                          str(chain["callee"]), bits)
        return {"kind": "alloc", "size": size}, evidence
    if chain.get("kind") == "rip":
        address = chain.get("address")
        obj = _object_for(address, objects)
        if obj:
            return ({"kind": "global", "size": obj["size"], "symbol": obj["name"]},
                    f"全局对象 {obj['name']} 剩余容量 {obj['size']:#x} @ {chain.get('insn')}")
        # 无符号时退到段容量：`.bss`/`.data` 的大小来自段表真值，比“未解析”有用得多。
        section = _section_at(binary_path, address)
        if section is not None and address is not None:
            remaining = section["addr"] + section["size"] - int(address)
            if remaining > 0:
                name = section["name"] or hex(section["addr"])
                return ({"kind": "global", "size": remaining,
                         "symbol": f"{name}+0x{int(address) - section['addr']:x}",
                         "section": name},
                        f"段 {name} 内 offset 0x{int(address) - section['addr']:x}，"
                        f"剩余容量 {remaining:#x} @ {chain.get('insn')}")
        return {"kind": "global"}, f"rip 相对全局地址 @ {chain.get('insn')}"
    if chain.get("kind") == "param":
        return {"kind": "param", "index": chain["index"]}, str(chain.get("reason") or "函数参数")
    return None, str(chain.get("reason") or "目的缓冲不可解析")


def _scan_input_site(lines: list[dict], index: int, callee: str, *,
                     objects: list[dict] | None = None, bits: int = 64,
                     got_base: int | None = None, binary_path=None) -> dict:
    """有界读/gets 调用点的长度与目的缓冲解析。"""
    if callee in _PRODUCT_LENGTH_ARGS:
        factors = [_arg_chain(lines, index, arg, bits, got_base)
                   for arg in _PRODUCT_LENGTH_ARGS[callee]]
        if all(chain.get("kind") == "imm" for chain in factors):
            length_chain = {"kind": "imm",
                            "value": int(factors[0]["value"]) * int(factors[1]["value"]),
                            "insn": " × ".join(str(chain.get("insn") or "") for chain in factors),
                            "factors": factors}
        else:
            length_chain = {"kind": "unknown", "reason": "元素大小或数量非常量",
                            "factors": factors}
    else:
        length_chain = _backtrack(lines, index, _LENGTH_REG.get(callee, "rdx"),
                                  got_base=got_base)
    dest_chain = _backtrack(lines, index, _DEST_REG.get(callee, "rdi"),
                            got_base=got_base)
    length = length_chain.get("value") if length_chain.get("kind") == "imm" else None
    length_evidence = length_chain.get("insn") or length_chain.get("reason") or ""
    dest, dest_evidence = _resolve_dest(lines, dest_chain, objects=objects, bits=bits,
                                        binary_path=binary_path)
    if callee in _UNBOUNDED:
        length = None
        length_evidence = "gets 无长度参数（无界输入）"
    return {"length": length, "length_evidence": length_evidence,
            "dest": dest, "dest_evidence": dest_evidence,
            "canary_offset": _canary_offset(lines),
            "fmt": None, "length_chain": length_chain, "dest_chain": dest_chain}


def _cdecl_pushes(lines: list[dict], index: int) -> list[tuple[int, str]]:
    """Return cdecl arguments nearest-first as (instruction index, operand)."""
    pushes: list[tuple[int, str]] = []
    for pos in range(index - 1, max(-1, index - 32), -1):
        text = str(lines[pos].get("text") or "").strip()
        if text.startswith(("call", "jmp", "ret")):
            break
        match = re.match(r"^push[l]?\s+(.+)$", text)
        if match:
            pushes.append((pos, match[1].strip()))
    return pushes


def _scan_input_site_i386(lines: list[dict], index: int, callee: str, *,
                          objects: list[dict] | None = None,
                          binary_path=None) -> dict:
    length = None
    length_evidence = "无长度参数" if callee in _UNBOUNDED else "长度参数不可解析"
    length_index = _I386_LENGTH_ARG.get(callee)
    if callee in _PRODUCT_LENGTH_ARGS:
        factors = [_arg_chain(lines, index, arg, 32) for arg in _PRODUCT_LENGTH_ARGS[callee]]
        if all(chain.get("kind") == "imm" for chain in factors):
            length_chain = {"kind": "imm",
                            "value": int(factors[0]["value"]) * int(factors[1]["value"]),
                            "insn": " × ".join(str(chain.get("insn") or "") for chain in factors)}
        else:
            length_chain = {"kind": "unknown", "reason": "元素大小或数量非常量"}
    else:
        length_chain = (_arg_chain(lines, index, length_index, 32)
                        if length_index is not None else
                        {"kind": "unknown", "reason": "无长度参数"})
    if length_chain.get("kind") == "imm":
        length = int(length_chain["value"])
        length_evidence = str(length_chain.get("insn") or "cdecl 长度立即数")
    dest_index = _I386_DEST_ARG.get(callee)
    dest_chain = (_arg_chain(lines, index, dest_index, 32)
                  if dest_index is not None else {"kind": "unknown", "reason": "无目的参数"})
    dest, dest_evidence = _resolve_dest(lines, dest_chain, objects=objects, bits=32,
                                        binary_path=binary_path)
    if dest_chain.get("kind") == "imm" and int(dest_chain.get("value") or 0):
        obj = _object_for(int(dest_chain["value"]), objects)
        dest = ({"kind": "global", "size": obj["size"], "symbol": obj["name"]}
                if obj else {"kind": "global"})
        dest_evidence = (f"绝对全局对象 {obj['name']} 容量 {obj['size']:#x}"
                         if obj else f"绝对全局地址 {dest_chain['value']:#x}")
    return {"length": length, "length_evidence": length_evidence,
            "dest": dest, "dest_evidence": dest_evidence,
            "canary_offset": None, "word_size": 4, "fmt": None,
            "length_chain": length_chain, "dest_chain": dest_chain}


def _scan_sprintf_site(lines: list[dict], index: int, binary_path, *,
                       objects: list[dict] | None = None) -> dict:
    """sprintf(dst, fmt, ...)：目的缓冲 + 格式串是否含 %s。"""
    resolved = _scan_input_site(lines, index, "strcpy", objects=objects)
    resolved["callee_hint"] = "sprintf"
    resolved["fmt"] = _resolve_fmt_string(lines, index, "rsi", binary_path)
    return resolved


_FMT_STR = re.compile(rb"[\x20-\x7e]{2,64}")


def _resolve_fmt_string(lines: list[dict], index: int, reg: str,
                        binary_path, *, written: set[int] | None = None) -> dict:
    """回溯格式串寄存器 → rip 相对目标 → 读文件内字符串。

    地址固定 ≠ 内容固定：落在可写段（.bss/.data/.got）的“格式串”会在运行时
    被改写，必须按数据流处理而不是当作字面量。实测 2023 春秋杯 easy_LzhiFTP
    的 `fgets(.bss,8,stdin)` → `printf(同一 .bss)` 就属于这种情况。
    """
    fmt_chain = _backtrack(lines, index, reg)
    if fmt_chain.get("kind") != "rip":
        return {"resolved": False, "reason": "格式串不是可证明的固定字符串",
                "chain": fmt_chain}
    target = fmt_chain.get("address")
    if target is None:
        return {"resolved": False, "reason": "rip 目标地址缺失", "chain": fmt_chain}
    section = _section_at(binary_path, target)
    if section is not None and (section["flags"] & SHF_WRITE):
        name = section["name"] or hex(section["addr"])
        proven = bool(written) and int(target) in written
        return {"resolved": False, "writable": True, "address": int(target),
                "written": proven,
                "reason": (f"格式串地址落在可写段 {name}，"
                           + ("且本函数已写入该地址" if proven
                              else "内容可能已被运行时改写")),
                "chain": fmt_chain}
    from pwncraft.core.workbench import elf_geometry, vaddr_to_offset
    geo = elf_geometry(binary_path)
    off = vaddr_to_offset(geo, target)
    if off is None:
        # 只读段之外（无文件映像且非可写段）→ 内容不可判定
        return {"resolved": False, "unmapped": True,
                "reason": f"格式串地址 {target:#x} 不落在任何段", "chain": fmt_chain}
    data = Path(binary_path).read_bytes()[off:off + 96]
    chunk = _FMT_STR.match(data)
    fmt = chunk.group(0).decode() if chunk else ""
    return {"resolved": True, "fmt": fmt, "chain": fmt_chain}


def _read_literal(binary_path, address) -> dict:
    """读地址处的字符串，并区分只读段（真字面量）与可写段（内容可变）。"""
    if not address:
        return {"resolved": False, "reason": "格式串地址缺失"}
    section = _section_at(binary_path, address)
    if section is not None and (section["flags"] & SHF_WRITE):
        name = section["name"] or hex(section["addr"])
        return {"resolved": False, "writable": True, "address": int(address),
                "reason": f"格式串地址落在可写段 {name}，内容可能已被运行时改写"}
    from pwncraft.core.workbench import elf_geometry, vaddr_to_offset
    try:
        geo = elf_geometry(binary_path)
    except (ValueError, OSError):
        return {"resolved": False, "reason": "ELF 解析失败"}
    off = vaddr_to_offset(geo, int(address))
    if off is None:
        return {"resolved": False, "unmapped": True,
                "reason": f"格式串地址 {int(address):#x} 不落在任何段"}
    try:
        data = Path(binary_path).read_bytes()[off:off + 96]
    except OSError:
        return {"resolved": False, "reason": "ELF 读取失败"}
    chunk = _FMT_STR.match(data)
    return {"resolved": True, "fmt": chunk.group(0).decode() if chunk else ""}


def _resolve_fmt_chain(lines: list[dict], chain: dict, binary_path) -> dict:
    """把 _arg_chain 的结果（imm/rip 地址）解析成字符串。

    i386 上格式串几乎总是 `push $imm` 或 `lea -X(%ebx),%eax; push %eax`，
    因此必须同时接受 imm 与 rip 两种来源，否则 32 位题的格式化字符串面
    会整体退化成一堆 unknown_format（实测 p2048 的 16 处 __printf_chk）。
    """
    kind = chain.get("kind")
    if kind == "rip":
        address = chain.get("address")
    elif kind == "imm":
        address = chain.get("value")
    else:
        return {"resolved": False, "reason": f"格式串不是固定地址（{kind}）",
                "chain": chain}
    result = _read_literal(binary_path, address)
    result["chain"] = chain
    return result


def _scanf_dangerous(lines: list[dict], index: int, binary_path) -> dict:
    """scanf(fmt, ...)：解析 rip 相对格式串，仅无宽度 %s 判险。"""
    check = _resolve_fmt_string(lines, index, "rdi", binary_path)
    if not check.get("resolved"):
        return {"danger": None, "reason": check["reason"]}
    fmt = check.get("fmt") or ""
    if re.search(r"%[0-9]*[lhz]*s", fmt) and not re.search(r"%[0-9]+[lhz]*s", fmt):
        return {"danger": True, "reason": f'格式串 "{fmt}" 含无宽度 %s', "fmt": fmt}
    return {"danger": False, "reason": f'格式串 "{fmt}" 无无宽度 %s', "fmt": fmt}


def _format_finding(lines: list[dict], index: int, callee: str, binary_path,
                    bits: int, written: set[int] | None = None,
                    got_base: int | None = None) -> dict:
    fmt_index = _fmt_arg_index(callee, bits)
    if bits == 32:
        # i386：格式串来自 `push $imm` 或 `lea -X(%ebx),%eax`；两条路径都要认，
        # 否则 32 位题的格式化字符串面全部退化成 unknown_format。
        chain = _arg_chain(lines, index, fmt_index, 32, got_base)
        check = _resolve_fmt_chain(lines, chain, binary_path)
    else:
        check = _resolve_fmt_string(lines, index, _ARG_REGS[fmt_index], binary_path,
                                    written=written)
    if check.get("resolved"):
        fmt = str(check.get("fmt") or "")
        if re.search(r"%(?:\d+\$)?n", fmt):
            return {"verdict": "format_write_candidate", "category": "format_string",
                    "severity": "high", "confidence": "format_literal",
                    "reason": f'{callee} 固定格式串含 %n："{fmt}"',
                    "evidence": [str(check.get("chain", {}).get("insn") or "固定格式串")]}
        return {"verdict": "within_bound", "category": "format_string",
                "severity": "info", "confidence": "proven_literal",
                "reason": f'{callee} 使用固定格式串："{fmt}"', "evidence": []}
    if check.get("writable"):
        section = _section_at(binary_path, int(check.get("address") or 0))
        name = (section or {}).get("name") or hex(int(check.get("address") or 0))
        slot = f"{name}+0x{int(check['address']) - int((section or {}).get('addr') or 0):x}"
        if check.get("written"):
            return {"verdict": "format_string_candidate", "category": "format_string",
                    "severity": "critical", "confidence": "dataflow",
                    "reason": f"{callee} 的格式串位于可写段 {slot}，且本函数写入过该地址（内容可控）",
                    "evidence": [str(check.get("reason") or ""), slot]}
        return {"verdict": "mutable_format_slot", "category": "format_string",
                "severity": "high", "confidence": "review",
                "reason": (f"{callee} 的格式串位于可写段 {slot}：地址固定但内容可在运行时被改写，"
                           "需确认是否存在写入该槽位的输入路径"),
                "evidence": [slot]}
    chain = check.get("chain") or {}
    if chain.get("kind") in {"stack", "slot", "alloc", "param", "mem"}:
        return {"verdict": "format_string_candidate", "category": "format_string",
                "severity": "critical", "confidence": "dataflow",
                "reason": f"{callee} 格式参数来自非固定数据（{chain.get('reason') or chain.get('kind')}）",
                "evidence": [str(chain.get("insn") or check.get("reason") or "数据流回溯")]}
    return {"verdict": "unknown_format", "category": "format_string",
            "severity": "medium", "confidence": "review", "reason": str(check.get("reason")),
            "evidence": []}


_BACKDOOR_COMMAND = re.compile(
    r"cat\s|/bin/sh|/bin/bash|sh\s+-c|flag|/ctf|readflag|getflag|exec\s", re.I)


def _backdoor_finding(lines: list[dict], index: int, callee: str, bits: int,
                      binary_path, chain: dict) -> dict | None:
    """常量参数的命令执行 = 硬编码后门（**不是**「安全」）。

    原实现把「参数是固定字符串」判为 `within_bound`(info)。但对 CTF/AWDP 题而言，
    `system("cat /ctfshow_flag")` 恰恰是最直接的后门：无污点、无内存破坏、
    从 main 直线可达即可拿 flag。实测 07_堆利用-前置基础 的 pwn_135/137/138
    三题全部是这种形态，旧规则判 info → 整类召回 0。
    只读段里的常量字符串才按后门处理；可写段走 mutable_* 分支。
    """
    address = chain.get("address") if chain.get("kind") == "rip" else chain.get("value")
    if address is None:
        return None
    section = _section_at(binary_path, address)
    if section is not None and (section["flags"] & SHF_WRITE):
        return None                       # 可写段由 _command_finding 处理
    literal = _read_literal(binary_path, address)
    text = str(literal.get("fmt") or "")
    if not text:
        return None
    if not _BACKDOOR_COMMAND.search(text):
        return None
    where = hex(int(address))
    return {
        "verdict": "hardcoded_command_backdoor",
        "category": "command_execution",
        "severity": "critical",
        "confidence": "dataflow",
        "reason": (f"{callee} 以只读段常量字符串为命令直接执行：\"{text}\"（{where}）；"
                   "无输入参与即达成命令执行，属硬编码后门"),
        "evidence": [f"0x{lines[index]['address']:x}: {lines[index]['text']}",
                     f"{where}: \"{text}\""],
    }


def _command_finding(lines: list[dict], index: int, callee: str,
                     bits: int, binary_path=None, written: set[int] | None = None,
                     got_base: int | None = None) -> dict:
    chain = _arg_chain(lines, index, _COMMAND_SPECS[callee], bits, got_base)
    backdoor = _backdoor_finding(lines, index, callee, bits, binary_path, chain)
    if backdoor is not None:
        return backdoor
    # i386 用 `push $imm` 传字面量地址；64 位用 rip 相对寻址。两者都要按
    # 「段可写性」判定：只读段才是真固定字符串（p2048/p2048 的 /bin/sh 即如此）。
    if chain.get("kind") in {"rip", "imm"}:
        address = (chain.get("address") if chain["kind"] == "rip"
                   else chain.get("value"))
        section = _section_at(binary_path, address)
        if section is not None and (section["flags"] & SHF_WRITE):
            name = section["name"] or hex(section["addr"])
            proven = bool(written) and int(address or 0) in written
            if proven:
                return {"verdict": "command_injection_candidate",
                        "category": "command_execution", "severity": "critical",
                        "confidence": "dataflow",
                        "reason": (f"{callee} 的命令参数位于可写段 {name}，"
                                   "且本函数写入过该地址（内容可控）"),
                        "evidence": [str(chain.get("insn") or ""), name]}
            return {"verdict": "mutable_command_slot",
                    "category": "command_execution", "severity": "high",
                    "confidence": "review",
                    "reason": (f"{callee} 的命令参数位于可写段 {name}：地址固定但内容可被运行时改写，"
                               "需确认写入路径是否可控"),
                    "evidence": [name]}
        return {"verdict": "within_bound", "category": "command_execution",
                "severity": "info", "confidence": "fixed_argument",
                "reason": (f"{callee} 的程序/命令参数为只读段固定字符串"
                           f"{'（' + (section or {}).get('name', '') + '）' if section else ''}，"
                           "需确认是否为必要业务"),
                "evidence": [str(chain.get("insn") or "固定地址参数")]}
    if chain.get("kind") in {"stack", "slot", "alloc", "param", "mem"}:
        return {"verdict": "command_injection_candidate", "category": "command_execution",
                "severity": "critical", "confidence": "dataflow",
                "reason": f"{callee} 的程序/命令参数来自可变数据（{chain.get('reason') or chain.get('kind')}）",
                "evidence": [str(chain.get("insn") or "参数定义链")]}
    return {"verdict": "command_execution_candidate", "category": "command_execution",
            "severity": "high", "confidence": "dangerous_api",
            "reason": f"{callee} 可启动进程，参数来源未能证明为固定值",
            "evidence": [str(chain.get("reason") or "参数定义链中断")]}


def _verdict(callee: str, resolved: dict) -> dict:
    length = resolved.get("length")
    dest = resolved.get("dest")
    evidence = [e for e in (resolved.get("length_evidence"),
                            resolved.get("dest_evidence")) if e]
    if callee in _UNBOUNDED:
        if dest and dest["kind"] == "stack":
            return {"verdict": "overflow_confirmed",
                    "reason": f"gets 无界输入写入栈缓冲（rbp-{dest['offset']:#x}）",
                    "evidence": evidence}
        if dest and dest["kind"] == "global":
            return {"verdict": "global_write_candidate",
                    "reason": "gets 写入全局缓冲", "evidence": evidence}
        return {"verdict": "unknown_buffer", "reason": "目的缓冲不可解析",
                "evidence": evidence}
    if callee in _UNBOUNDED_WRITE:
        fmt_info = resolved.get("fmt")
        if (callee == "sprintf" and fmt_info is not None
                and not fmt_info.get("danger")
                and fmt_info.get("resolved")):
            return {"verdict": "unknown_length",
                    "reason": (f"sprintf 固定格式串 \"{fmt_info.get('fmt')}\" 无无界 %s，"
                               "但格式化结果长度仍未证明小于目标容量"),
                    "evidence": evidence}
        if dest and dest["kind"] == "stack":
            return {"verdict": "unbounded_input",
                    "reason": (f"{callee} 向栈缓冲无界写入（rbp-{dest['offset']:#x}；"
                               "源长度未解析，需复核可控性）"),
                    "evidence": evidence}
        if dest and dest["kind"] == "global":
            return {"verdict": "global_write_candidate",
                    "reason": f"{callee} 写全局缓冲（槽不匹配需人工复核）",
                    "evidence": evidence}
        return {"verdict": "unknown_buffer", "reason": "目的缓冲不可解析",
                "evidence": evidence}
    if length is None:
        return {"verdict": "unknown_length", "reason": "长度来源非常量（寄存器/变量）",
                "evidence": evidence}
    if dest is None:
        return {"verdict": "unknown_buffer", "reason": "目的缓冲不可解析（长度已知）",
                "evidence": evidence}
    if dest["kind"] == "param":
        return {"verdict": "unknown_buffer",
                "reason": f"目的缓冲来自函数参数 {dest['index'] + 1}，等待调用者传播",
                "evidence": evidence}
    if dest["kind"] == "alloc":
        if dest.get("size") is None:
            return {"verdict": "unknown_buffer", "reason": "分配尺寸非常量",
                    "evidence": evidence}
        bound = dest["size"]
        if length > bound:
            return {"verdict": "overflow_confirmed",
                    "reason": f"长度 {length:#x} > 分配尺寸 {bound:#x}",
                    "bound": bound, "evidence": evidence}
        return {"verdict": "within_bound",
                "reason": f"长度 {length:#x} ≤ 分配尺寸 {bound:#x}（mmap/malloc 同尺寸）",
                "bound": bound, "evidence": evidence}
    if dest["kind"] == "global":
        if dest.get("size") is not None:
            bound = int(dest["size"])
            if length > bound:
                return {"verdict": "overflow_confirmed",
                        "reason": (f"长度 {length:#x} > 全局对象 {dest.get('symbol', '')}"
                                   f"剩余容量 {bound:#x}"),
                        "bound": bound, "evidence": evidence}
            return {"verdict": "within_bound",
                    "reason": (f"长度 {length:#x} ≤ 全局对象 {dest.get('symbol', '')}"
                               f"剩余容量 {bound:#x}"),
                    "bound": bound, "evidence": evidence}
        return {"verdict": "global_write_candidate",
                "reason": "写入全局缓冲（段/符号尺寸未解析，槽不匹配需人工复核）",
                "evidence": evidence}
    canary = resolved.get("canary_offset") is not None
    bound_canary = dest["offset"] - (8 if canary else 0)
    word_size = int(resolved.get("word_size") or 8)
    bound_rip = dest["offset"] + word_size    # buf 起点到保存返回地址的距离
    if length > bound_rip:
        return {"verdict": "overflow_confirmed",
                "reason": (f"长度 {length:#x} 覆盖返回地址（rbp-{dest['offset']:#x}"
                           f"{'，含 canary' if canary else ''}，返回地址距 buf {bound_rip:#x}）"),
                "bound": bound_rip, "evidence": evidence}
    if length > bound_canary:
        return {"verdict": "overflow_confirmed",
                "reason": (f"长度 {length:#x} 破坏 canary/保存 RBP"
                           f"（rbp-{dest['offset']:#x}，可用 {bound_canary:#x}）"),
                "bound": bound_canary, "evidence": evidence}
    return {"verdict": "within_bound",
            "reason": f"长度 {length:#x} ≤ 栈缓冲 {bound_canary:#x}",
            "bound": bound_canary, "evidence": evidence}


_VERDICT_META = {
    "overflow_confirmed": ("critical", "proven", "memory_corruption"),
    "pointer_step_overflow": ("critical", "dataflow", "memory_corruption"),
    "off_by_one_null_write": ("critical", "dataflow", "memory_corruption"),
    "array_index_off_by_one": ("critical", "dataflow", "memory_corruption"),
    "array_index_signed_bypass": ("high", "dataflow", "memory_corruption"),
    "array_index_unchecked": ("high", "dataflow", "memory_corruption"),
    "invalid_free_confirmed": ("critical", "proven", "heap_lifetime"),
    "format_string_candidate": ("critical", "dataflow", "format_string"),
    "command_injection_candidate": ("critical", "dataflow", "command_execution"),
    "hardcoded_command_backdoor": ("critical", "dataflow", "command_execution"),
    "unbounded_input": ("high", "dangerous_api", "memory_corruption"),
    "double_free_candidate": ("high", "lifecycle", "heap_lifetime"),
    "use_after_free_candidate": ("high", "lifecycle", "heap_lifetime"),
    "stack_address_return": ("high", "dataflow", "lifetime"),
    "format_write_candidate": ("high", "format_literal", "format_string"),
    "mutable_format_slot": ("high", "review", "format_string"),
    "mutable_command_slot": ("high", "review", "command_execution"),
    "command_execution_candidate": ("high", "dangerous_api", "command_execution"),
    "global_write_candidate": ("medium", "review", "memory_corruption"),
    "unknown_length": ("medium", "review", "memory_corruption"),
    "unknown_buffer": ("medium", "review", "memory_corruption"),
    "unknown_format": ("medium", "review", "format_string"),
    "within_bound": ("info", "proven_safe_site", "reviewed_site"),
}


def _decorate(verdict: dict) -> dict:
    severity, confidence, category = _VERDICT_META.get(
        str(verdict.get("verdict")), ("medium", "review", "unknown"))
    result = {**verdict}
    result.setdefault("severity", severity)
    result.setdefault("confidence", confidence)
    result.setdefault("category", category)
    result.setdefault("remediation", {
        "memory_corruption": "按证据中的真实对象容量收紧长度，或在完整指令边界增加显式边界检查。",
        "heap_lifetime": "释放后立即清空所有者槽位，并保证每条错误路径只释放一次。",
        "format_string": "把格式参数改为固定字符串；输出外部数据时使用固定的 %s。",
        "command_execution": "移除不必要的命令执行；必要时使用固定程序和参数白名单。",
        "lifetime": "不要返回当前栈帧内对象地址，改由调用者提供缓冲区或使用堆对象。",
    }.get(str(result["category"]), "结合调用路径和运行时输入继续复核。"))
    return result


_PTR_STEP_INC = re.compile(r"^inc\s+%(\w+)$")
_PTR_STEP_STORE = re.compile(r"^mov[a-z]?\s+[^,]+,-?0x[0-9a-fA-F]*\(%(\w+)\)$")
_PTR_STEP_CMP = re.compile(r"^(?:cmp|test)[a-z]?\s")
_PTR_STEP_BRANCH = re.compile(
    r"^(?:jmpq?|j(?:a|ae|b|be|g|ge|l|le|e|ne|z|nz|s|ns|o|no|p|np|c|nc))\s")
_BACKWARD_TARGET = re.compile(r"^jmpq?\s+([0-9a-fA-F]+)")
_REG_TOKEN = re.compile(r"%([a-z][a-z0-9]{0,3})")


def _mentions_register(text: str, register: str) -> bool:
    """指令是否引用了该寄存器（任意宽度别名，经 _norm 归一）。"""
    wanted = _norm(register)
    return any(_norm(token) == wanted for token in _REG_TOKEN.findall(text))


def _pointer_step_points(function: dict, lines: list[dict], bits: int) -> list[dict]:
    """无界指针步进写：`inc REG` + `mov ...,-K(REG)` 且同段内没有上界比较。

    这类循环不经过任何 libc 输入函数，长度参数无从收紧——传统“危险 API + 长度”
    规则完全看不见它。实测 2023 春秋杯 p2048 的 game 主循环即为此形态：
    `mov [edi-1],al` 配合 `inc edi`，1024 字节缓冲被任意长度输入写穿。
    判定刻意保守：只认“自增寄存器既是写基址、循环体内又无 cmp/test 分支”。
    """
    points: list[dict] = []
    if not lines:
        return points
    for index, insn in enumerate(lines):
        inc = _PTR_STEP_INC.match(str(insn.get("text") or "").strip())
        if not inc:
            continue
        register = _norm(inc[1])
        # 1) 自增之后紧跟写内存，且基址就是这个自增寄存器。
        #    （真实形态：`inc edi` → `mov %al,-0x1(%edi)`）
        store_index = None
        for probe in range(index + 1, min(len(lines), index + 9)):
            text = str(lines[probe].get("text") or "").strip()
            if text.startswith(("ret", "call")):
                break
            store = _PTR_STEP_STORE.match(text)
            if store and _norm(store[1]) == register:
                store_index = probe
                break
        if store_index is None:
            continue
        # 2) 写之后必须有回跳（循环），否则不是步进写循环。
        branch_index = None
        for probe in range(store_index + 1, min(len(lines), store_index + 13)):
            text = str(lines[probe].get("text") or "").strip()
            if text.startswith("ret"):
                break
            if _PTR_STEP_BRANCH.match(text):
                branch_index = probe
                break
        if branch_index is None:
            continue
        # 3) 真正的循环体里没有任何**针对该指针**的上界比较 → 写入长度由输入决定。
        #    只能算“引用该寄存器”的比较：大循环体里必然存在大量与指针无关的
        #    cmp（实测 p2048 的 game 主循环用 cmpb 做按键分发），把它们当护栏
        #    会让真漏洞静默消失。
        #    循环体 = 回跳目标 .. 回跳点；没有可解析的回跳目标时退化为回跳点前的
        #    有界窗口。
        branch_addr = int(lines[branch_index]["address"])
        target_match = _BACKWARD_TARGET.match(str(lines[branch_index].get("text") or "").strip())
        loop_start = index
        if target_match:
            target = int(target_match[1], 16)
            loop_start = next((position for position, item in enumerate(lines)
                               if int(item["address"]) >= target), index)
        body = [str(item.get("text") or "")
                for item in lines[loop_start:branch_index + 1]]
        if any(_PTR_STEP_CMP.match(item) and _mentions_register(item, register)
               for item in body):
            continue
        write = str(lines[store_index].get("text") or "").strip()
        points.append({
            "function": str(function.get("name")),
            "vaddr": f"0x{lines[store_index]['address']:x}",
            "callee": "mem-write-loop",
            **_decorate({
                "verdict": "pointer_step_overflow",
                "reason": (f"指针 {register} 无界自增后写内存"
                           f"（0x{lines[store_index]['address']:x} {write}），"
                           "循环体内无上界比较：写入长度由输入长度决定"),
                "evidence": [f"0x{insn['address']:x}: {insn['text']}",
                             f"0x{lines[store_index]['address']:x}: {write}",
                             "循环内未发现 cmp/test 上界检查"]}),
            "length": None, "buffer": {"kind": "stack"},
        })
    return points


_OB1_ADD = re.compile(r"^add\s+%(\w+),%(\w+)$")
_OB1_BYTE_STORE = re.compile(
    r"^movb?\s+\$0x([0-9a-fA-F]+),(?:-?0x[0-9a-fA-F]*)?\(%(\w+)\)$")


def _value_key(chain: dict):
    """把定义链压成可比较的身份（同一栈槽/同一立即数/同一全局地址）。"""
    kind = chain.get("kind")
    if kind == "slot":
        return ("slot", int(chain.get("offset") or 0))
    if kind == "imm":
        return ("imm", int(chain.get("value") or 0))
    if kind == "rip":
        return ("rip", int(chain.get("address") or 0))
    if kind == "stack":
        return ("stack", int(chain.get("offset") or 0))
    return None


def _off_by_one_points(function: dict, lines: list[dict], bits: int,
                       objects: list[dict] | None, binary_path,
                       got_base: int | None = None) -> list[dict]:
    """off-by-one 终止符写：`read(buf, n)` 之后写 `buf[n]`。

    典型形态（实测 2023 春秋杯 babyaul 的 add_chunk）：
        call read            ; read(0, ptrs[i], size)
        ...
        mov  -0xc(%rbp),%eax ; eax = size（与 read 的长度是同一栈槽）
        add  %rdx,%rax       ; rax = buf + size
        movb $0x0,(%rax)     ; buf[size] = 0   ← 越界 1 字节 NUL
    判据只认可证明的部分：写入地址由「读入长度」参与相加，且写的是常量字节。
    """
    points: list[dict] = []
    if bits != 64:
        return points
    for index, insn in enumerate(lines):
        call = _CALL_PLT.match(str(insn.get("text") or ""))
        if not call:
            continue
        callee = canonical_callee(call[1])
        if callee not in _DEST_REG or callee in _PRODUCT_LENGTH_ARGS:
            continue
        length_reg = _LENGTH_REG.get(callee)
        if length_reg is None:
            continue
        length_key = _value_key(_backtrack(lines, index, length_reg, got_base=got_base))
        if length_key is None:
            continue
        dest, dest_evidence = _resolve_dest(
            lines, _backtrack(lines, index, _DEST_REG[callee], got_base=got_base),
            objects=objects, bits=bits, binary_path=binary_path)
        if dest is None:
            continue
        for probe in range(index + 1, min(len(lines), index + 48)):
            text = str(lines[probe].get("text") or "").strip()
            # 不能在 `ret` 处中断：编译器会生成 `push x; addq $8,(%rsp); ret`
            # 这类跳板（实测 babyaul 0x64ec 正是如此），它落在写入点之前，
            # 提前 break 会漏掉真正的 off-by-one。函数边界已由 FDE 精确给出。
            if text.startswith("call"):
                break
            add = _OB1_ADD.match(text)
            if not add:
                continue
            base = _norm(add[2])
            for follow in range(probe + 1, min(len(lines), probe + 4)):
                store = _OB1_BYTE_STORE.match(str(lines[follow].get("text") or "").strip())
                if not store or _norm(store[2]) != base:
                    continue
                # 相加的两个操作数之一必须与本读的长度同源
                matched = None
                for register in (_norm(add[1]), base):
                    key = _value_key(_backtrack(lines, probe, register, got_base=got_base))
                    if key is not None and key == length_key:
                        matched = register
                        break
                if matched is None:
                    continue
                # glibc 可用区精化：`malloc(n)` 的可用区是 align16(n+8)-8，
                # 只有 n%16==8 时 `buf[n]=0` 才真的越界；其余落在可用区内。
                # 同函数内若存在尺寸来源等同于该读入长度的 malloc，就用它判定。
                alloc_key = None
                for probe_call in range(max(0, index - 64), index):
                    call_text = str(lines[probe_call].get("text") or "")
                    alloc = _CALL_PLT.match(call_text)
                    if not alloc:
                        continue
                    name = canonical_callee(alloc[1])
                    if _alloc_size_key(lines, probe_call, name, got_base) == length_key:
                        alloc_key = probe_call
                        break
                note = ""
                if alloc_key is not None:
                    if length_key[0] == "imm":
                        usable = _usable_size(int(length_key[1]))
                        if int(length_key[1]) < usable:
                            continue          # 终止符落在可用区内 → 不是漏洞
                        note = (f"；malloc 尺寸 {int(length_key[1]):#x}，"
                                f"可用区 {usable:#x}，终止符恰好越界")
                    else:
                        note = ("；该尺寸来自 malloc 同一来源，当且仅当 size%16==8 "
                                "时可用区等于 size，终止符才落到下一 chunk 头部")
                points.append({
                    "function": str(function.get("name")),
                    "vaddr": f"0x{lines[follow]['address']:x}",
                    "callee": f"{callee}+term",
                    **_decorate({
                        "verdict": "off_by_one_null_write",
                        "reason": (f"{callee} 读入长度与写入下标同源："
                                   f"0x{lines[follow]['address']:x} 处写 "
                                   f"buf[长度]（{store[1]}），越界 1 字节。{dest_evidence}{note}"),
                        "evidence": [f"0x{insn['address']:x}: {insn['text']}",
                                     f"0x{lines[probe]['address']:x}: {text}",
                                     f"0x{lines[follow]['address']:x}: "
                                     f"{lines[follow]['text']}"]}),
                    "length": None, "buffer": dest,
                })
                break
    return points


def _array_bases(parsed: list[tuple[dict, list[dict]]]) -> set[int]:
    """收集所有「被用作带步长索引的数组基址」的全局地址。

    只用这些地址推断邻居容量：数组中间的标量引用（如 `mov 0x4a98(%rip),%eax`）
    不是数组边界，拿它当边界会把容量算小并产生 off-by-one 误报
    （实测 easy_LzhiFTP 会算出 3 个元素）。
    """
    bases: set[int] = set()
    for _, lines in parsed:
        for index, insn in enumerate(lines):
            if not _INDEX_SCALE.match(str(insn.get("text") or "").strip()):
                continue
            for probe in range(index + 1, min(len(lines), index + 5)):
                text = str(lines[probe].get("text") or "").strip()
                match = _ARRAY_BASE.match(text)
                if match:
                    comment = _RIP_COMMENT.search(text)
                    if comment:
                        bases.add(int(comment[1], 16))
                    break
    return bases


def _array_extent(binary_path, base: int, stride: int, array_bases: set[int],
                  objects: list[dict] | None) -> tuple[int, str] | None:
    """推断全局数组占用字节数，并返回推断依据。

    优先级：readelf OBJECT 符号（精确）→ 相邻数组基址（数组布局）→ 段末尾（保守）。
    数组布局依据实测有效：easy_LzhiFTP 的 0x4a80 之上最近的数组基址是 0x4b00，
    0x80/8 = 16 个元素，与人工逆向一致。
    """
    obj = _object_for(base, objects)
    if obj and int(obj["size"]) >= stride:
        return int(obj["size"]), f"符号 {obj['name']} 容量 {int(obj['size']):#x}"
    neighbours = [b for b in array_bases if b >= base + stride and b - base <= 0x2000]
    if neighbours:
        nearest = min(neighbours)
        return nearest - base, f"相邻数组基址 {nearest:#x}"
    section = _section_at(binary_path, base)
    if section:
        end = section["addr"] + section["size"]
        if end >= base + stride:
            return end - base, f"段 {section['name'] or hex(section['addr'])} 末尾"
    return None


def _guard_for(lines: list[dict], before: int, index_key, got_base: int | None):
    """找到保护该数组访问的常量上界比较，返回 (立即数, 条件跳转助记符)。"""
    for pos in range(before - 1, max(-1, before - 64), -1):
        text = str(lines[pos].get("text") or "").strip()
        # 只在真正的控制流边界停：`call` 会返回、条件跳转可能是别的检查，
        # 二者都不影响上界比较对本次访问的支配关系。实测 easy_LzhiFTP 的
        # guard 与数组访问之间就夹着 `call strlen` 和另一个 `cmp/jbe`。
        # `jmp`/`ret` 才是块边界（跨过它们可能匹配到上一个块的陈旧比较）。
        if text.startswith(("ret", "jmp")):
            return None
        match = _CMP_IMM_REG.match(text)
        key = None
        immediate = None
        if match:
            immediate = int(match[1], 0)
            key = _value_key(_backtrack(lines, pos, match[2], got_base=got_base))
        else:
            memory = _CMP_IMM_SLOT.match(text)
            if memory:
                immediate = int(memory[1], 0)
                key = ("slot", abs(int(memory[2], 16)))
        if key is None or immediate is None:
            continue
        if key != index_key:
            continue
        if pos + 1 >= len(lines):
            return None
        jump = _COND_JUMP.match(str(lines[pos + 1].get("text") or "").strip())
        if jump:
            return immediate, jump[1]
        return None
    return None


def _has_lower_bound(lines: list[dict], around: int, index_key) -> bool:
    """是否存在排除负值的下界检查（`cmp $0,x; js` / `test x,x; js`）。"""
    for pos in range(max(0, around - 96), min(len(lines), around + 8)):
        text = str(lines[pos].get("text") or "").strip()
        probe_key = None
        if _TEST_SELF.match(text):
            probe_key = _value_key(
                _backtrack(lines, pos, _TEST_SELF.match(text)[1]))
        else:
            zero = _CMP_ZERO.match(text)
            if zero:
                probe_key = _value_key(_backtrack(lines, pos, zero[1]))
        if probe_key is None or probe_key != index_key:
            continue
        for follow in range(pos + 1, min(len(lines), pos + 3)):
            jump = _COND_JUMP.match(str(lines[follow].get("text") or "").strip())
            if jump and jump[1] in {"js", "jl", "jge", "jns"}:
                return True
    return False


def _slot_source_call(lines: list[dict], before: int, offset: int) -> str:
    """回溯栈槽的写入来源，返回写入前最近的一次调用名。"""
    pattern = re.compile(rf",-?0x{offset:x}\(%[er]bp\)$")
    for pos in range(before - 1, max(-1, before - 96), -1):
        if not pattern.search(str(lines[pos].get("text") or "").strip()):
            continue
        for probe in range(pos - 1, max(-1, pos - 8), -1):
            call = _CALL_PLT.match(str(lines[probe].get("text") or "").strip())
            if call:
                return call[1].split("@", 1)[0]
            if str(lines[probe].get("text") or "").startswith("ret"):
                break
        return ""
    return ""


def _slot_input_source(lines: list[dict], before: int, offset: int) -> str:
    """识别 scanf/read 直接把输入写到目标栈槽的情形。

    scanf 的 dest 通过 lea stack-slot,reg 传参，调用后通常没有一条显式
    mov 写回栈槽；因此不能只依赖 _slot_source_call 的写栈槽形态。
    """
    direct = _slot_source_call(lines, before, offset)
    if direct in _INPUT_PARSE_CALLS:
        return direct
    needle = f"-0x{offset:x}(%rbp)"
    for pos in range(before - 1, max(-1, before - 160), -1):
        call = _CALL_PLT.match(str(lines[pos].get("text") or "").strip())
        if not call:
            continue
        symbol = call[1].split("@", 1)[0]
        if symbol not in _INPUT_PARSE_CALLS:
            continue
        window = " ".join(str(lines[i].get("text") or "")
                           for i in range(max(0, pos - 8), pos))
        if needle in window:
            return symbol
    return ""


def _array_index_points(function: dict, lines: list[dict], bits: int,
                        array_bases: set[int], objects: list[dict] | None,
                        binary_path, got_base: int | None = None) -> list[dict]:
    """全局数组的索引边界：上界 off-by-one 与有符号索引绕过。

    实测 2023 春秋杯 easy_LzhiFTP 的两处真实漏洞：
      * touch：`cmp $0x10,%eax; jg error` 后 `lea (,%rax,8)` 写入 0x4a80 ——
        数组 16 个元素（0..15），而 0x10 被放行 → 越界写到相邻的 0x4b00。
      * edit ：`cmp $0xf,%eax; jg error`（**有符号**）后 `mov (,%rax,8)(0x4b00),%rax`
        再 `read(0,rax,0x20)` —— idx 来自 atoi，负值通过 → 越界取指针 → 任意地址写。
    """
    points: list[dict] = []
    if bits != 64:
        return points
    for index, insn in enumerate(lines):
        scale = _INDEX_SCALE.match(str(insn.get("text") or "").strip())
        if not scale:
            continue
        index_reg, stride = _norm(scale[1]), int(scale[2])
        base = None
        for probe in range(index + 1, min(len(lines), index + 5)):
            text = str(lines[probe].get("text") or "").strip()
            match = _ARRAY_BASE.match(text)
            if match:
                comment = _RIP_COMMENT.search(text)
                if comment:
                    base = int(comment[1], 16)
                break
        if base is None:
            continue
        extent_info = _array_extent(binary_path, base, stride, array_bases, objects)
        if extent_info is None:
            continue
        extent, extent_basis = extent_info
        count = extent // stride
        if not 2 <= count <= 4096:
            continue
        index_key = _value_key(_backtrack(lines, index, index_reg, got_base=got_base))
        if index_key is None:
            continue
        guard = _guard_for(lines, index, index_key, got_base)
        section = _section_at(binary_path, base)
        where = f"{(section or {}).get('name') or hex(base)}+0x{base - ((section or {}).get('addr') or base):x}"
        source = ""
        if index_key[0] == "slot":
            source = _slot_input_source(lines, index, int(index_key[1]))
        if guard is None:
            # 仅在全局数组容量、比例寻址、输入来源均已证明时上报；没有
            # cmp/test guard 的索引不能因旧逻辑而静默跳过。
            if source in _INPUT_PARSE_CALLS:
                points.append({
                    "function": str(function.get("name")),
                    "vaddr": f"0x{insn['address']:x}", "callee": "array-index",
                    **_decorate({
                        "verdict": "array_index_unchecked",
                        "reason": (f"数组 {where} 的下标来自 {source} 解析的输入，"
                                   "该访问前未找到上界或下界检查：可能越界读写指针"),
                        "evidence": [f"0x{insn['address']:x}: {insn['text']}",
                                     f"下标 ← {source}",
                                     f"数组基址 {base:#x}，stride {stride}，容量 {extent:#x} → {count} 个元素（{extent_basis}）",
                                     "未见可关联的 cmp/test + 条件跳转 guard"]}),
                    "length": None, "buffer": {"kind": "global", "symbol": where},
                })
            continue
        immediate, jump = guard
        if immediate >= count:
            points.append({
                "function": str(function.get("name")),
                "vaddr": f"0x{insn['address']:x}", "callee": "array-index",
                **_decorate({
                    "verdict": "array_index_off_by_one",
                    "reason": (f"数组 {where}（stride {stride}，推断 {count} 个元素，"
                               f"下标 0..{count - 1}；依据：{extent_basis}）"
                               f"的上界比较为 {immediate:#x}，放行了越界下标 {count}"),
                    "evidence": [f"数组基址 {base:#x}，stride {stride}，"
                                 f"容量 {extent:#x} → {count} 个元素（{extent_basis}）",
                                 f"0x{insn['address']:x}: {insn['text']}",
                                 f"上界比较立即数 {immediate:#x}（{jump}）"]}),
                "length": None, "buffer": {"kind": "global", "symbol": where},
            })
        elif jump in _SIGNED_JUMPS:
            if source in _INPUT_PARSE_CALLS and not _has_lower_bound(lines, index, index_key):
                points.append({
                    "function": str(function.get("name")),
                    "vaddr": f"0x{insn['address']:x}", "callee": "array-index",
                    **_decorate({
                        "verdict": "array_index_signed_bypass",
                        "reason": (f"数组 {where} 的下标来自 {source} 解析的输入，"
                                   f"上界用有符号比较（{jump} {immediate:#x}）且无下界检查："
                                   "负下标可绕过并越界读写指针"),
                        "evidence": [f"0x{insn['address']:x}: {insn['text']}",
                                     f"0x{lines[index]['address']:x}: 下标 ← {source}",
                                     f"有符号上界 {immediate:#x}，未见 cmp $0/test 下界检查"]}),
                    "length": None, "buffer": {"kind": "global", "symbol": where},
                })
    return points


def _alloc_size_key(lines: list[dict], index: int, callee: str,
                    got_base: int | None) -> tuple | None:
    """同一函数内找到 `malloc(size)` 的尺寸来源身份。"""
    if callee not in _ALLOC_SPECS:
        return None
    chain = _arg_chain(lines, index, _ALLOC_SPECS[callee][0], 64, got_base)
    return _value_key(chain)


def _usable_size(size: int) -> int:
    """glibc `malloc_usable_size`：`align16(size + 8) - 8`。

    只有 `size % 16 == 8` 时 usable == size，`buf[size] = 0` 才真的越界；
    否则该字节仍落在可用区内（实测 babyaul：0x100 落在 usable 0x108 内不算漏洞，
    0x18 / 0x4f8 才越界）。
    """
    return ((size + 8 + 15) & ~15) - 8


_INDIRECT_CALL = re.compile(
    r"^call\w*\s+\*(-?(?:0x[0-9a-fA-F]+)?\(%[er](?:bp|sp)\))$")
_LEA_SLOT = re.compile(r"^lea\w*\s+(-?(?:0x[0-9a-fA-F]+)?\(%[er](?:bp|sp)\)),%(\w+)$")
_SCANF_FAMILY = {"scanf", "__isoc99_scanf", "fscanf", "__isoc99_fscanf",
                 "sscanf", "__isoc99_sscanf", "vscanf"}
_NUMERIC_CONV = re.compile(r"%[0-9]*[lhqjzt]*[diuoxXp]")
_CALL_ANY = re.compile(r"^call\w*\s+[0-9a-fA-F]+\s+<([^>]+)>")


def _input_controlled_call_points(function: dict, lines: list[dict], bits: int,
                                  binary_path) -> list[dict]:
    """输入标量被当作函数指针调用（`scanf("%llu",&slot)` → `call *slot`）。

    这是 13_PWN技巧 整类的主导形态（实测 pwn_311/312/313：菜单选 2 直接把用户
    输入的整数当函数指针调用，参数硬编码 "/bin/bash"）。它不含任何缓冲区越界：
    `fwrite`/`read` 的长度都是常量，所以「危险 API + 长度」规则判安全；格式串是
    常量，格式串规则也判安全。真正被污染的是**控制流目标**。
    判据：间接调用的内存操作数与某个 scanf 族调用的目标槽**操作数文本一致**，
    且该 scanf 的格式串含数值转换（`%llu/%ld/%d/%p…`）。
    """
    points: list[dict] = []
    for index, insn in enumerate(lines):
        text = str(insn.get("text") or "").strip()
        call = _INDIRECT_CALL.match(text)
        if not call:
            continue
        operand = call[1]
        for probe in range(index - 1, max(-1, index - 40), -1):
            probe_text = str(lines[probe].get("text") or "").strip()
            if probe_text.startswith("ret"):
                break
            direct = _CALL_ANY.match(probe_text)
            if not direct:
                continue
            callee = canonical_callee(direct[1])
            if callee not in _SCANF_FAMILY:
                continue
            # 该 scanf 的目标槽是否就是这个操作数（lea 后紧邻调用）
            slot_hit = False
            for back in range(probe - 1, max(-1, probe - 8), -1):
                lea = _LEA_SLOT.match(str(lines[back].get("text") or "").strip())
                if lea and lea[1] == operand:
                    slot_hit = True
                    break
                if str(lines[back].get("text") or "").startswith("call"):
                    break
            if not slot_hit:
                continue
            fmt = ""
            check = _resolve_fmt_string(lines, probe, "rdi", binary_path)
            if check.get("resolved"):
                fmt = str(check.get("fmt") or "")
            elif bits == 32:
                chain = _arg_chain(lines, probe, _SCANF_SPECS.get(callee, (0, 1))[0], 32)
                fmt = str(_resolve_fmt_chain(lines, chain, binary_path).get("fmt") or "")
            numeric = bool(_NUMERIC_CONV.search(fmt)) if fmt else True
            if not numeric:
                continue
            points.append({
                "function": str(function.get("name")),
                "vaddr": f"0x{insn['address']:x}",
                "callee": "indirect-call",
                **_decorate({
                    "verdict": "input_controlled_call",
                    "reason": (f"{callee} 把用户输入写入 {operand}"
                               f"（0x{lines[probe]['address']:x}，格式串 \"{fmt or '?'}\"），"
                               f"0x{insn['address']:x} 直接把该槽当函数指针调用："
                               "控制流目标由输入决定"),
                    "evidence": [f"0x{lines[probe]['address']:x}: {lines[probe]['text']}",
                                 f"0x{insn['address']:x}: {text}",
                                 f"目标槽 {operand} 由输入标量控制"]}),
                "length": None, "buffer": {"kind": "stack"},
            })
            break
    return points


def _slot_version(lines: list[dict], before: int, offset: int) -> int:
    pattern = re.compile(rf",-?0x{offset:x}\(%[er]bp\)$")
    for pos in range(before - 1, -1, -1):
        if pattern.search(str(lines[pos].get("text") or "")):
            return int(lines[pos]["address"])
    return 0


def _pointer_key(lines: list[dict], index: int, arg_index: int, bits: int) -> tuple | None:
    chain = _arg_chain(lines, index, arg_index, bits)
    if chain.get("kind") == "slot":
        offset = int(chain["offset"])
        return ("slot", offset, _slot_version(lines, index, offset))
    if chain.get("kind") == "stack":
        return ("stack", int(chain["offset"]))
    if chain.get("kind") == "rip":
        return ("global", int(chain.get("address") or 0))
    return None


def _lifetime_points(function: dict, lines: list[dict], bits: int) -> list[dict]:
    points: list[dict] = []
    freed: dict[tuple, tuple[int, str]] = {}
    for index, insn in enumerate(lines):
        call = _CALL_PLT.match(str(insn.get("text") or ""))
        if not call:
            if str(insn.get("text") or "").startswith("ret") and bits == 64:
                chain = _backtrack(lines, index, "rax")
                if chain.get("kind") == "stack":
                    points.append({"function": str(function.get("name")),
                                   "vaddr": f"0x{insn['address']:x}", "callee": "ret",
                                   **_decorate({"verdict": "stack_address_return",
                                                "reason": (f"返回当前栈帧地址 rbp-{chain['offset']:#x}，"
                                                           "函数返回后立即失效"),
                                                "evidence": [str(chain.get("insn"))]})})
            continue
        callee = canonical_callee(call[1])
        if callee == "free":
            chain = _arg_chain(lines, index, 0, bits)
            if chain.get("kind") == "stack":
                points.append({"function": str(function.get("name")),
                               "vaddr": f"0x{insn['address']:x}", "callee": callee,
                               **_decorate({"verdict": "invalid_free_confirmed",
                                            "reason": f"free 接收到栈地址 rbp-{chain['offset']:#x}",
                                            "evidence": [str(chain.get("insn"))]})})
                continue
            key = _pointer_key(lines, index, 0, bits)
            if key is not None:
                if key in freed:
                    first, _ = freed[key]
                    points.append({"function": str(function.get("name")),
                                   "vaddr": f"0x{insn['address']:x}", "callee": callee,
                                   **_decorate({"verdict": "double_free_candidate",
                                                "reason": f"同一指针槽位在 0x{first:x} 后再次 free",
                                                "evidence": [f"first free @ 0x{first:x}",
                                                             f"second free @ 0x{insn['address']:x}"]})})
                else:
                    freed[key] = (int(insn["address"]), callee)
            continue
        for arg_index in _POINTER_USE_ARGS.get(callee, ()):
            key = _pointer_key(lines, index, arg_index, bits)
            if key is not None and key in freed:
                first, _ = freed[key]
                points.append({"function": str(function.get("name")),
                               "vaddr": f"0x{insn['address']:x}", "callee": callee,
                               **_decorate({"verdict": "use_after_free_candidate",
                                            "reason": f"参数 {arg_index + 1} 使用已在 0x{first:x} 释放的指针槽位",
                                            "evidence": [f"free @ 0x{first:x}",
                                                         f"use @ 0x{insn['address']:x}"]})})
                break
    return points


def _wrapper_summaries(parsed: list[tuple[dict, list[dict]]], bits: int,
                       objects: list[dict] | None) -> dict[str, list[dict]]:
    if bits != 64:
        return {}
    summaries: dict[str, list[dict]] = {}
    for function, lines in parsed:
        for index, insn in enumerate(lines):
            call = _CALL_PLT.match(str(insn.get("text") or ""))
            if not call:
                continue
            sink = canonical_callee(call[1])
            if sink not in _DEST_REG:
                continue
            resolved = _scan_input_site(lines, index, sink, objects=objects)
            dest_chain, length_chain = resolved["dest_chain"], resolved["length_chain"]
            if dest_chain.get("kind") != "param":
                continue
            if sink not in _UNBOUNDED and length_chain.get("kind") != "param":
                continue
            summaries.setdefault(str(function.get("name")), []).append({
                "sink": sink, "dest_arg": int(dest_chain["index"]),
                "length_arg": (int(length_chain["index"])
                               if length_chain.get("kind") == "param" else None),
                "evidence": f"0x{insn['address']:x}: {sink}",
            })
    return summaries


def scan_functions(functions: list[dict], *, binary_path=None, bits: int = 64,
                   objects: list[dict] | None = None) -> list[dict]:
    """扫描调用点、格式参数、命令来源、包装器与堆生命周期（纯函数）。"""
    points: list[dict] = []
    parsed = [(fn, parse_instruction_lines(fn.get("assembly") or "")) for fn in functions]
    wrappers = _wrapper_summaries(parsed, int(bits), objects)
    array_bases = _array_bases(parsed) if int(bits) == 64 else set()
    for fn, lines in parsed:
        if not lines:
            continue
        got_base = _i386_got_base(lines) if int(bits) == 32 else None
        written = _written_globals(lines, int(bits), got_base)
        points.extend(_lifetime_points(fn, lines, int(bits)))
        points.extend(_pointer_step_points(fn, lines, int(bits)))
        if int(bits) == 64:
            points.extend(_off_by_one_points(fn, lines, int(bits), objects,
                                             binary_path, got_base))
            points.extend(_array_index_points(fn, lines, int(bits), array_bases,
                                              objects, binary_path, got_base))
        for index, insn in enumerate(lines):
            call = _CALL_PLT.match(insn["text"] or "")
            if not call:
                continue
            callee = call[1].split("@", 1)[0].split("+", 1)[0]
            callee = canonical_callee(callee)   # 静态 glibc / fortify 内部名
            if callee in _DEST_REG:
                if int(bits) == 32:
                    resolved = _scan_input_site_i386(lines, index, callee, objects=objects,
                                                 binary_path=binary_path)
                elif callee in {"sprintf", "vsprintf"}:
                    resolved = _scan_sprintf_site(lines, index, binary_path, objects=objects)
                else:
                    resolved = _scan_input_site(lines, index, callee, objects=objects,
                                                bits=int(bits), got_base=got_base,
                                                binary_path=binary_path)
                verdict = _decorate(_verdict(callee, resolved))
            elif callee in _SCANF_SPECS:
                fmt_index, dest_index = _SCANF_SPECS[callee]
                if int(bits) == 64:
                    check = _resolve_fmt_string(lines, index, _ARG_REGS[fmt_index],
                                                binary_path, written=written)
                else:
                    check = {"resolved": False, "reason": "i386 格式串内容暂不可读取",
                             "chain": _arg_chain(lines, index, fmt_index, 32,
                                                 got_base=got_base)}
                fmt = str(check.get("fmt") or "")
                danger = (bool(re.search(r"%[0-9]*[lhz]*s", fmt))
                          and not bool(re.search(r"%[0-9]+[lhz]*s", fmt))) if check.get("resolved") else None
                dest_chain = _arg_chain(lines, index, dest_index, int(bits),
                                        got_base=got_base)
                dest = None
                if dest_chain.get("kind") == "stack":
                    dest = {"kind": "stack", "offset": dest_chain["offset"]}
                elif dest_chain.get("kind") == "rip":
                    dest = {"kind": "global"}
                if danger:
                    reason = f'格式串 "{fmt}" 含无宽度 %s'
                    resolved = {"length": None, "length_evidence": reason,
                                "dest": dest, "dest_evidence": "scanf %s 第二参数",
                                "canary_offset": None}
                    verdict = _decorate(_verdict("gets", resolved))
                    verdict["reason"] = f"{callee}: {reason} → {verdict['reason']}"
                else:
                    resolved = {"length": None,
                                "length_evidence": (f'固定格式串 "{fmt}"' if check.get("resolved")
                                                    else str(check.get("reason") or "")),
                                "dest": None, "dest_evidence": "",
                                "canary_offset": None}
                    verdict = _decorate({"verdict": "within_bound" if danger is False
                                        else "unknown_format",
                                        "reason": (f"{callee}: 固定格式串未发现无宽度 %s"
                                                   if danger is False else
                                                   f"{callee}: {check.get('reason')}"),
                                        "evidence": []})
            elif callee in _FORMAT_SPECS:
                resolved = {"length": None, "dest": None}
                verdict = _decorate(_format_finding(lines, index, callee, binary_path,
                                                    int(bits), written, got_base))
            elif callee in _COMMAND_SPECS:
                resolved = {"length": None, "dest": None}
                verdict = _decorate(_command_finding(lines, index, callee, int(bits),
                                                     binary_path, written, got_base))
            else:
                wrapper_specs = wrappers.get(callee, ())
                for spec in wrapper_specs:
                    dest_chain = _arg_chain(lines, index, int(spec["dest_arg"]), int(bits))
                    dest, dest_evidence = _resolve_dest(
                        lines, dest_chain, objects=objects, bits=int(bits))
                    length_chain = (_arg_chain(lines, index, int(spec["length_arg"]), int(bits))
                                    if spec["length_arg"] is not None else
                                    {"kind": "unknown", "reason": "无长度参数"})
                    length = (int(length_chain["value"])
                              if length_chain.get("kind") == "imm" else None)
                    inherited = {"length": length,
                                 "length_evidence": str(length_chain.get("insn") or
                                                        length_chain.get("reason") or ""),
                                 "dest": dest, "dest_evidence": dest_evidence,
                                 "canary_offset": _canary_offset(lines),
                                 "word_size": 4 if int(bits) == 32 else 8}
                    derived = _decorate(_verdict(str(spec["sink"]), inherited))
                    derived["reason"] = f"经 {callee} → {spec['sink']}：{derived['reason']}"
                    points.append({"function": str(fn.get("name")),
                                   "vaddr": f"0x{insn['address']:x}",
                                   "callee": str(spec["sink"]), "via": callee,
                                   **derived, "length": length, "buffer": dest})
                continue
            point = {
                "function": str(fn.get("name")),
                "vaddr": f"0x{insn['address']:x}",
                "callee": callee,
                **verdict,
                "length": resolved.get("length"),
                "buffer": resolved.get("dest"),
            }
            if (point["verdict"] == "overflow_confirmed" and callee in
                    {"read", "recv", "recvfrom", "fgets"} and verdict.get("bound")):
                length_insn = str(resolved.get("length_chain", {}).get("insn") or "")
                if length_insn.startswith("0x"):
                    point["request"] = {"kind": "readlen", "function": str(fn.get("name")),
                                        "callee": callee, "size": hex(max(1, int(verdict["bound"]))),
                                        "vaddr": length_insn}
            points.append(point)
            if callee in _FORMAT_SPECS and callee in _DEST_REG:
                format_verdict = _decorate(
                    _format_finding(lines, index, callee, binary_path, int(bits), written,
                                    got_base))
                points.append({"function": str(fn.get("name")),
                               "vaddr": f"0x{insn['address']:x}", "callee": callee,
                               "facet": "format", **format_verdict,
                               "length": None, "buffer": None})
    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    points.sort(key=lambda p: (severity_order.get(str(p.get("severity")), 9),
                               str(p.get("verdict")), int(str(p["vaddr"]), 16)))
    return points


_RAW_INSN = re.compile(r"^\s*([0-9a-fA-F]+):\s")
_FDE_PC = re.compile(r"\bpc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)")


def parse_fde_ranges(frames_output: str) -> list[tuple[int, int]]:
    """从 `readelf --debug-dump=frames` 提取 [(pc_begin, pc_end)]。

    不手写 DWARF 解码：FDE 的指针宽度由 CIE 的 augmentation 'R' 决定
    （x86-64 gcc 默认 pcrel|sdata4，即 4 字节而非 8），猜错会算出完全错误的
    边界。readelf 已经是本扫描器的既有依赖，直接采信它的输出。
    """
    ranges: list[tuple[int, int]] = []
    for line in str(frames_output or "").splitlines():
        match = _FDE_PC.search(line)
        if match:
            begin = int(match[1], 16)
            stop = int(match[2], 16)
            if stop > begin:
                ranges.append((begin, stop))
    return ranges


def recover_functions(disassembly: str, frames_output: str,
                      text_section: dict | None) -> list[dict]:
    """无本地符号时，用 .eh_frame 的 FDE 把单个 `.text` blob 切回函数。

    `objdump -d` 对 `-s` 过的二进制只输出一个 `<.text>`，所有发现都归到同一个
    「函数」，跨函数/包装器/生命周期分析随之失效。`.eh_frame` 是异常处理必需
    的，strip 后仍保留，每个 FDE 恰好覆盖一个函数。
    实测 2023 春秋杯：easy_LzhiFTP 由 1 块恢复成 9 个函数、babyaul 恢复成 277 个。
    """
    if not text_section:
        return []
    ranges = parse_fde_ranges(frames_output)
    if not ranges:
        return []
    lo = int(text_section.get("addr") or 0)
    hi = lo + int(text_section.get("size") or 0)

    rows: list[tuple[int, str]] = []
    for line in str(disassembly).splitlines():
        match = _RAW_INSN.match(line)
        if match:
            rows.append((int(match[1], 16), line.rstrip()))
    rows = [(addr, raw) for addr, raw in rows if lo <= addr < hi]
    if not rows:
        return []
    rows.sort(key=lambda item: item[0])

    cut = sorted({begin for begin, _ in ranges if lo < begin < hi})
    if not cut:
        return []
    bounds = [lo] + cut + [hi]
    functions: list[dict] = []
    for index in range(len(bounds) - 1):
        begin, stop = bounds[index], bounds[index + 1]
        body = [raw for addr, raw in rows if begin <= addr < stop]
        if not body:
            continue
        functions.append({"name": f"sub_{begin:x}", "address": hex(begin),
                          "section": ".text", "lines": body,
                          "instruction_count": len(body), "truncated": False,
                          "assembly": "\n".join(body), "recovered": "eh_frame"})
    return functions


def _parse_object_symbols(output: str) -> list[dict]:
    objects: list[dict] = []
    pattern = re.compile(
        r"^\s*\d+:\s*([0-9a-fA-F]+)\s+(\d+)\s+OBJECT\s+\w+\s+\w+\s+(\S+)\s+(.+?)\s*$")
    for line in str(output or "").splitlines():
        match = pattern.match(line)
        if not match or match[3] in {"UND", "ABS"} or int(match[2]) <= 0:
            continue
        name = match[4].split("@", 1)[0]
        objects.append({"address": int(match[1], 16), "size": int(match[2]), "name": name})
    objects.sort(key=lambda item: (item["address"], -item["size"], item["name"]))
    unique: list[dict] = []
    seen = set()
    for item in objects:
        key = (item["address"], item["size"])
        if key not in seen:
            unique.append(item)
            seen.add(key)
    return unique


def scan_vuln_points(binary, runner, *, functions: list[dict] | None = None,
                     objects: list[dict] | None = None) -> dict:
    """扫描目标 ELF；objdump 分析代码，readelf 补充全局对象容量。"""
    recovered = 0
    if functions is None:
        result = runner.run_tool(
            "objdump", ["-d", "--insn-width=16", "--", runner.to_wsl_path(binary)])
        if not result.ok:
            output = result.combined_output()
            # 非 x86（如 AWDP 常见 MIPS/ARM 嵌入式题）宿主 objdump 无法反汇编。
            # 明说架构问题与解决方式，别让调用方以为目标文件损坏。
            if "can't disassemble" in output or "file format not recognized" in output:
                raise ValueError(
                    f"objdump 不支持该架构，需要 multiarch 工具链"
                    f"（如 mipsel-linux-gnu-objdump / aarch64-linux-gnu-objdump）："
                    f"{binary}。{output[:160]}")
            raise ValueError(f"objdump 失败: {output[:160]}")
        from pwncraft.core.code_analysis import parse_disassembly
        # 静态链接二进制函数动辄数千：默认 1000 上限会把目标函数截掉
        functions = parse_disassembly(result.stdout, max_functions=200000)["functions"]
        # 无本地符号时 objdump 只给一个 <.text>；用 .eh_frame 的 FDE 切回函数，
        # 否则跨函数分析（包装器传播、生命周期、函数级归因）全部失效。
        sections = _elf_sections(binary)
        text_section = next((s for s in sections
                             if s["name"] == ".text" and s["size"]), None)
        if text_section is None:
            # 段名不可解析时退化为取最大的可执行段（flags & 0x4 = SHF_EXECINSTR）
            loads = [s for s in sections if (s["flags"] & 0x4) and s["size"]]
            text_section = max(loads, key=lambda s: s["size"]) if loads else None
        # 触发条件：某个“函数”跨越了 .text 的大部分地址空间 —— 这就是 objdump
        # 在缺本地符号时吐出的整段 blob。**不能靠函数名判断**：objdump 会拿最近的
        # 动态符号拼出 `err@@Base-0xb6f` 这类合成名（实测 2025 长城杯 minidb），
        # 名字不带 `.` 前缀，按名判定会整题跳过恢复。
        ordered = sorted(functions, key=lambda fn: int(str(fn.get("address") or "0x0"), 16))
        text_lo = int(text_section.get("addr") or 0)
        text_hi = text_lo + int(text_section.get("size") or 0)
        widest = 0
        for position, fn in enumerate(ordered):
            begin = int(str(fn.get("address") or "0x0"), 16)
            if not (text_lo <= begin < text_hi):
                continue
            stop = text_hi
            for follower in ordered[position + 1:]:
                candidate = int(str(follower.get("address") or "0x0"), 16)
                if candidate > begin:
                    stop = candidate
                    break
            widest = max(widest, stop - begin)
        blob_only = bool(text_section.get("size")) and widest >= int(text_section["size"]) * 0.5
        if blob_only and text_section is not None:
            frames = runner.run_tool(
                "readelf", ["--debug-dump=frames", "--", runner.to_wsl_path(binary)])
            rebuilt = recover_functions(result.stdout, frames.stdout if frames.ok else "",
                                        text_section)
            # 不能要求“函数数变多”：原 24 条里多数是 .plt 桩，真实用户代码只是
            # 一个 blob。判据是恢复确实切出了多个函数，且覆盖了 blob 里的绝大部分
            # 指令（用 span 内的指令数当基准，与触发判据同源）。
            blob_instructions = sum(int(fn.get("instruction_count") or 0)
                                    for fn in ordered
                                    if text_lo <= int(str(fn.get("address") or "0x0"), 16) < text_hi)
            if len(rebuilt) >= 2:
                covered = sum(int(fn.get("instruction_count") or 0) for fn in rebuilt)
                if covered >= max(1, blob_instructions) * 0.8:
                    recovered = len(rebuilt)
                    # 只保留 .text **之外**的原函数（.plt/.init/.fini 等桩），
                    # 段内的原 blob 已被 rebuilt 取代。按名字过滤不够：
                    # objdump 的合成名 `err@@Base-0xb6f` 不带 `.` 前缀，
                    # 会被留下来和重建函数重复计数（实测 minidb 每个发现报两遍）。
                    keep = [fn for fn in functions
                            if not (text_lo <= int(str(fn.get("address") or "0x0"), 16) < text_hi)]
                    functions = rebuilt + keep
    if objects is None:
        symbols = runner.run_tool("readelf", ["-Ws", "--", runner.to_wsl_path(binary)])
        objects = _parse_object_symbols(symbols.stdout) if symbols.ok else []
    from pwncraft.core.workbench import elf_geometry
    bits = 64 if elf_geometry(binary)["is64"] else 32
    points = scan_functions(functions, binary_path=Path(binary), bits=bits, objects=objects)
    confirmed = sum(1 for p in points
                    if p["confidence"] in {"proven", "dataflow", "lifecycle"})
    risk_points = [p for p in points if p["severity"] in {"critical", "high", "medium"}]
    severity = {name: sum(1 for p in points if p["severity"] == name)
                for name in ("critical", "high", "medium", "info")}
    categories: dict[str, int] = {}
    for point in risk_points:
        name = str(point.get("category") or "unknown")
        categories[name] = categories.get(name, 0) + 1
    return {"binary": str(binary), "bits": bits, "points": points,
            "confirmed": confirmed, "risk_total": len(risk_points), "total": len(points),
            "severity": severity, "categories": categories,
            "coverage": {"functions": len(functions),
                         "functions_recovered": recovered,
                         "call_sites": sum(1 for fn in functions for insn in
                                           parse_instruction_lines(fn.get("assembly") or "")
                                           if _CALL_PLT.match(str(insn.get("text") or ""))),
                         "global_objects": len(objects),
                         "rules": (len(_BOUNDED_SPECS) + len(_UNBOUNDED_WRITE) +
                                   len(_FORMAT_SPECS) + len(_SCANF_SPECS) +
                                   len(_COMMAND_SPECS) + 6)},
            "limitations": [
                "静态分析不会执行目标；间接调用、自修改代码和深层跨函数数据流可能漏报。",
                "生命周期分析只报告同一函数、同一可追踪槽位的调用型证据。",
                "unknown 表示当前证据不足，不表示对应调用安全。",
                "可写段（.bss/.data）中的地址只是地址固定，内容仍可被运行时改写，"
                "这类槽位以 mutable_* 单独列出，需人工确认写入路径。",
            ]}
