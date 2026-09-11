"""漏洞点确认 v2：输入/无界写调用点的 定义-使用链 静态证明。

方法吸收自 intelpwn（guaidao2/intelpwn）的语义层 v2：从调用点**反向沿
定义链回溯**（`mov dst,src` 切换追踪目标），call/jmp/ret 截断、算术污染
判未知——破除固定窗口，编译器重排/长链不漏。本项目差异：AT&T 文本
（objdump）而非 capstone Intel；结论分五档诚实输出，绝不猜测。

检测面（v2）：
- 有界读 read/fgets：回溯 len_reg 定义链求常量 / buf_reg 定义链求栈槽或
  mmap·malloc 返回值；栈缓冲上界 = 槽偏移（rbp-X → 距 ret X+8、距 canary
  X-8），堆 = 分配尺寸常量。
- 无界读 gets：任何栈/堆目的即确认。
- scanf：解析格式串（rip 相对 → 文件偏移读字符串），仅无宽度 ``%s`` 判险。
- 无界写 strcpy/strcat/sprintf：栈目的 → 确认；全局（.bss/.data）→ 候选。
"""
from __future__ import annotations

from pathlib import Path

import re

from pwncraft.features.patch.patch_core import parse_instruction_lines

# amd64 SysV：read(fd,buf,len)→rdx/rsi；fgets(buf,size,f)→rsi/rdi；scanf(fmt,...)→rdi
_LENGTH_REG = {"read": "rdx", "fgets": "rsi"}
_DEST_REG = {"read": "rsi", "fgets": "rdi", "gets": "rdi",
             "strcpy": "rdi", "strcat": "rdi", "sprintf": "rdi"}
_UNBOUNDED = {"gets"}
_UNBOUNDED_WRITE = {"strcpy", "strcat", "sprintf"}
_ALLOC_SIZE_REG = {"mmap": "rsi", "malloc": "rdi", "calloc": "rdi"}

_LEA_RIP = re.compile(r"^lea\s+(?:-?0x[0-9a-fA-F]+)?\(%rip\),%(\w+)")
_LEA_RBP = re.compile(r"^lea\s+(-0x[0-9a-fA-F]+)\(%rbp\),%(\w+)$")
_MOV_REG_REG = re.compile(r"^mov\s+%(\w+),%(\w+)$")
_CALL_PLT = re.compile(r"^call[qw]?\s+[0-9a-fA-F]+\s+<([^>]+)>")
_CANARY_READ = re.compile(r"^mov\s+%fs:0x28,")

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
    return dst.strip().lstrip("%")


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


def _backtrack(lines: list[dict], call_index: int, reg: str, *,
               limit: int = BACKTRACK_LIMIT) -> dict:
    """反向定义链：追 reg 的最终定义。

    返回 {'kind': 'stack'|'imm'|'alloc'|'rip'|'unknown', ...}；
    call/jmp/ret 截断（跨块不猜），算术污染 → unknown。
    """
    target = _norm(reg)
    start = max(0, call_index - limit)
    for k in range(call_index - 1, start - 1, -1):
        insn = lines[k]
        text = insn["text"] or ""
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
            return {"kind": "rip", "insn": f"0x{insn['address']:x}"}
        if text.startswith("mov") and not text.startswith("movs"):
            ops = _mov_operands(text)
            if ops is None:
                continue
            src_op, dst_op = ops          # AT&T：第一操作数=源，第二=目的
            if dst_op.startswith("$") or not dst_op.startswith("%"):
                continue                   # 目的是内存/段寄存器 → 链断
            dst_reg = _norm(dst_op.lstrip("%"))
            if src_op.startswith("$"):
                if re.match(r"^\$-?0x[0-9a-fA-F]+$", src_op) and dst_reg == target:
                    value = int(src_op[1:], 16)
                    return {"kind": "imm", "value": value,
                            "insn": f"0x{insn['address']:x}"}
                continue
            src_reg = src_op.lstrip("%").split(",")[0]
            if dst_reg == target:
                if re.match(r"^[er]?[a-z0-9]{2,3}$", src_reg):
                    target = _norm(src_reg)   # mov dst,src → 沿源继续追
                    continue
                return {"kind": "mem", "reason": f"来源为内存 {src_op}"}
            continue
        for op in _ARITH:
            if text.startswith(op + " ") or text.startswith(op + "l ") \
                    or text.startswith(op + "q "):
                if _dst_reg(text) == target:
                    return {"kind": "unknown", "reason": f"{op} 污染"}
                break
    return {"kind": "unknown", "reason": "窗口起点仍未定"}


def _scan_input_site(lines: list[dict], index: int, callee: str) -> dict:
    """有界读/gets 调用点的长度与目的缓冲解析。"""
    length_chain = _backtrack(lines, index, _LENGTH_REG.get(callee, "rdx"))
    dest_chain = _backtrack(lines, index, _DEST_REG.get(callee, "rdi"))
    length = length_chain.get("value") if length_chain.get("kind") == "imm" else None
    length_evidence = length_chain.get("insn") or length_chain.get("reason") or ""
    dest, dest_evidence = None, ""
    if dest_chain.get("kind") == "stack":
        dest = {"kind": "stack", "offset": dest_chain["offset"]}
        dest_evidence = f"lea -{dest_chain['offset']:#x}(%rbp) @ {dest_chain['insn']}"
    elif dest_chain.get("kind") == "alloc":
        alloc = _backtrack(lines, dest_chain["alloc_insn"],
                           _ALLOC_SIZE_REG[dest_chain["callee"]])
        size = alloc.get("value") if alloc.get("kind") == "imm" else None
        if size is not None:
            dest = {"kind": "alloc", "size": size}
            dest_evidence = (f"{dest_chain['callee']} 返回 ← 尺寸 {size:#x} "
                             f"@ {alloc.get('insn')}")
        else:
            dest = {"kind": "alloc", "size": None}
            dest_evidence = f"{dest_chain['callee']} 返回（尺寸非常量）"
    elif dest_chain.get("kind") == "rip":
        dest = {"kind": "global"}
        dest_evidence = f"rip 相对全局地址 @ {dest_chain['insn']}"
    if callee in _UNBOUNDED:
        length = None
        length_evidence = "gets 无长度参数（无界输入）"
    return {"length": length, "length_evidence": length_evidence,
            "dest": dest, "dest_evidence": dest_evidence,
            "canary_offset": _canary_offset(lines),
            "fmt": None}


def _scan_sprintf_site(lines: list[dict], index: int, binary_path) -> dict:
    """sprintf(dst, fmt, ...)：目的缓冲 + 格式串是否含 %s。"""
    resolved = _scan_input_site(lines, index, "strcpy")
    resolved["callee_hint"] = "sprintf"
    resolved["fmt"] = _resolve_fmt_string(lines, index, "rsi", binary_path)
    return resolved


_FMT_STR = re.compile(rb"[\x20-\x7e]{2,64}")


def _resolve_fmt_string(lines: list[dict], index: int, reg: str,
                        binary_path) -> dict:
    """回溯格式串寄存器 → rip 相对目标 → 读文件内字符串。"""
    fmt_chain = _backtrack(lines, index, reg)
    if fmt_chain.get("kind") != "rip":
        return {"resolved": False, "reason": "格式串不可解析"}
    insn = next((i for i in lines
                 if f"0x{i['address']:x}" == fmt_chain.get("insn")), None)
    if insn is None or binary_path is None:
        return {"resolved": False, "reason": "格式串指令未定位"}
    m = re.search(r"#\s*([0-9a-fA-F]+)", insn["text"] or "")
    if not m:
        return {"resolved": False, "reason": "rip 目标地址缺失"}
    from pwncraft.core.workbench import elf_geometry, vaddr_to_offset
    target = int(m[1], 16)
    geo = elf_geometry(binary_path)
    off = vaddr_to_offset(geo, target)
    if off is None:
        return {"resolved": False, "reason": "格式串地址不在文件映像"}
    data = Path(binary_path).read_bytes()[off:off + 96]
    chunk = _FMT_STR.match(data)
    fmt = chunk.group(0).decode() if chunk else ""
    return {"resolved": True, "fmt": fmt}


def _scanf_dangerous(lines: list[dict], index: int, binary_path) -> dict:
    """scanf(fmt, ...)：解析 rip 相对格式串，仅无宽度 %s 判险。"""
    check = _resolve_fmt_string(lines, index, "rdi", binary_path)
    if not check.get("resolved"):
        return {"danger": None, "reason": check["reason"]}
    if fmt_chain.get("kind") != "rip":
        return {"danger": None, "reason": "格式串不可解析"}
    fmt = check.get("fmt") or ""
    if re.search(r"%[0-9]*[lhz]*s", fmt) and not re.search(r"%[0-9]+[lhz]*s", fmt):
        return {"danger": True, "reason": f'格式串 "{fmt}" 含无宽度 %s', "fmt": fmt}
    return {"danger": False, "reason": f'格式串 "{fmt}" 无无宽度 %s', "fmt": fmt}


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
            return {"verdict": "within_bound",
                    "reason": (f"sprintf 格式串 \"{fmt_info.get('fmt')}\" 无 %s"
                               "（数字/短串转换，缓冲足够）"),
                    "evidence": evidence}
        if dest and dest["kind"] == "stack":
            return {"verdict": "overflow_confirmed",
                    "reason": f"{callee} 无界写栈缓冲（rbp-{dest['offset']:#x}）",
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
        return {"verdict": "global_write_candidate",
                "reason": "写入全局缓冲（段/符号尺寸未解析，槽不匹配需人工复核）",
                "evidence": evidence}
    canary = resolved.get("canary_offset") is not None
    bound_canary = dest["offset"] - (8 if canary else 0)
    bound_rip = dest["offset"] + 8            # buf 起点到保存 RIP 的距离
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


def scan_functions(functions: list[dict], *, binary_path=None) -> list[dict]:
    """对已解析的函数列表扫描全部输入/无界写调用点（纯函数，便于单测）。"""
    points = []
    for fn in functions:
        lines = parse_instruction_lines(fn.get("assembly") or "")
        if not lines:
            continue
        for index, insn in enumerate(lines):
            call = _CALL_PLT.match(insn["text"] or "")
            if not call:
                continue
            callee = call[1].split("@")[0]
            callee = re.sub(r"^(?:_IO|__isoc99)_", "", callee)  # 静态 glibc 内部名
            if callee in ("read", "fgets", "gets", "strcpy", "strcat", "sprintf"):
                if callee == "sprintf":
                    resolved = _scan_sprintf_site(lines, index, binary_path)
                else:
                    resolved = _scan_input_site(lines, index, callee)
                verdict = _verdict(callee, resolved)
            elif callee in ("scanf", "fscanf"):
                check = _scanf_dangerous(lines, index, binary_path)
                dest_chain = _backtrack(lines, index, "rsi")
                dest = None
                if dest_chain.get("kind") == "stack":
                    dest = {"kind": "stack", "offset": dest_chain["offset"]}
                elif dest_chain.get("kind") == "rip":
                    dest = {"kind": "global"}
                if check.get("danger"):
                    resolved = {"length": None, "length_evidence": check["reason"],
                                "dest": dest, "dest_evidence": "scanf %s 第二参数",
                                "canary_offset": None}
                    verdict = _verdict("gets", resolved)
                    verdict["reason"] = f"scanf: {check['reason']} → {verdict['reason']}"
                else:
                    resolved = {"length": None,
                                "length_evidence": check.get("reason", ""),
                                "dest": None, "dest_evidence": "",
                                "canary_offset": None}
                    verdict = {"verdict": "within_bound" if check.get("danger") is False
                               else "unknown_buffer",
                               "reason": f"scanf: {check.get('reason')}",
                               "evidence": []}
            else:
                continue
            points.append({
                "function": str(fn.get("name")),
                "vaddr": f"0x{insn['address']:x}",
                "callee": callee,
                **verdict,
                "length": resolved.get("length"),
                "buffer": resolved.get("dest"),
            })
    order = {"overflow_confirmed": 0, "unbounded_input": 1,
             "global_write_candidate": 2, "unknown_length": 3,
             "unknown_buffer": 4, "within_bound": 5}
    points.sort(key=lambda p: (order.get(p["verdict"], 9), p["vaddr"]))
    return points


def scan_vuln_points(binary, runner, *, functions: list[dict] | None = None) -> dict:
    """扫描目标 ELF 的全部输入/无界写调用点（缺 functions 时自行 objdump）。"""
    if functions is None:
        result = runner.run_tool("objdump", ["-d", "--", runner.to_wsl_path(binary)])
        if not result.ok:
            raise ValueError(f"objdump 失败: {result.combined_output()[:120]}")
        from pwncraft.core.code_analysis import parse_disassembly
        # 静态链接二进制函数动辄数千：默认 1000 上限会把目标函数截掉
        functions = parse_disassembly(result.stdout, max_functions=200000)["functions"]
    points = scan_functions(functions, binary_path=Path(binary))
    confirmed = sum(1 for p in points
                    if p["verdict"] in ("overflow_confirmed", "unbounded_input"))
    return {"binary": str(binary), "points": points,
            "confirmed": confirmed, "total": len(points)}
