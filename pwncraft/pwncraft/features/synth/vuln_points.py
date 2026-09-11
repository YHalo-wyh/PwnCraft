"""漏洞点确认：read/fgets/gets 调用点的 长度 vs 缓冲区边界 静态证明。

设计边界（诚实结论，绝不猜测）：
- 对每个输入调用点解析三件事：长度来源（常量立即数 / 非常量）、
  目的缓冲区（栈槽偏移 / mmap·malloc 返回值 / 不可解析）、缓冲区上界
  （栈：buf 槽到保存 RBP 的距离减 canary 槽；堆/mmap：分配尺寸立即数）。
- 长度 > 上界 → ``overflow_confirmed``（两侧证据齐全才下结论）；
  长度 <= 上界 → ``within_bound``；gets 类无界输入 → ``unbounded_input``；
  任一侧解析不出 → ``unknown_buffer`` / ``unknown_length``，不下结论。
- 局限（显式）：仅 amd64 SysV 寄存器传参；AT&T 反汇编文本；调用点前向
  数据流窗口 ≤24 条；堆上界取分配点常量，尺寸来自变量时记 unknown。
"""
from __future__ import annotations

import re

from pwncraft.features.patch.patch_core import parse_instruction_lines

# amd64 SysV：read(fd, buf, len)→rdx=len/rsi=buf；fgets(buf, size, f)→esi=len/rdi=buf
_LENGTH_REG = {"read": "rdx", "fgets": "rsi"}
_DEST_REG = {"read": "rsi", "fgets": "rdi", "gets": "rdi"}
_UNBOUNDED = {"gets"}
_ALLOC_CALLEES = {"mmap": "rsi", "malloc": "edi", "calloc": "edi"}

_LEA_STACK_OFF = re.compile(r"^lea\s+(-0x[0-9a-fA-F]+)\(%r(?:bp|sp)\),%(\w+)$")
_MOV_IMM = re.compile(r"^mov\s+\$0x([0-9a-fA-F]+),%(\w+)$")
_MOV_RAX_TO = re.compile(r"^mov\s+%rax,%(\w+)$")
_MOV_REG_REG = re.compile(r"^mov\s+%(\w+),%(\w+)$")
_CALL_PLT = re.compile(r"^call[qw]?\s+[0-9a-fA-F]+\s+<([^>]+)>")
_CANARY_READ = re.compile(r"^mov\s+%fs:0x28,")

WINDOW = 24


def _norm(reg: str) -> str:
    """32 位寄存器名归一到 64 位（edx→rdx, esi→rsi, edi→rdi）。"""
    reg = reg.lower()
    if len(reg) == 3 and reg[0] == "e":
        return "r" + reg[1:]
    return reg


def _canary_offset(lines: list[dict]) -> int | None:
    """帧内 canary 槽：`mov %fs:0x28,%rX` 后紧跟 `mov %rX,-N(%rbp)`。"""
    for index, insn in enumerate(lines):
        if _CANARY_READ.match(insn["text"] or ""):
            # `mov %fs:0x28,%rax` —— 源寄存器在逗号之后（fs:0x28 段选择子含 %）
            src = (insn["text"] or "").split(",")[-1].strip().lstrip("%")
            for follow in lines[index + 1:index + 3]:
                m = re.match(rf"^mov\s+%{re.escape(src)},-?(0x[0-9a-fA-F]+)\(%rbp\)$",
                             follow["text"] or "")
                if m:
                    return int(m[1], 16)
    return None


def _resolve_site(lines: list[dict], index: int, callee: str) -> dict:
    """调用点前向数据流窗口：解析长度常量与目的缓冲区。"""
    length = None
    length_evidence = ""
    stack_tags: dict[str, int] = {}   # reg → rbp 偏移（正数）
    alloc_regs: dict[str, int] = {}   # reg → 分配尺寸
    pending_alloc = None              # 最近一次 alloc 调用等待 rax 拷贝的尺寸
    last_imm: dict[str, int] = {}     # reg → 窗口内最近立即数（alloc 尺寸候选）
    canary = _canary_offset(lines)

    start = max(0, index - WINDOW)
    for insn in lines[start:index]:
        text = insn["text"] or ""
        call = _CALL_PLT.match(text)
        if call:
            name = call[1].split("@")[0]
            size_reg = _ALLOC_CALLEES.get(name)
            if size_reg and last_imm.get(_norm(size_reg)) is not None:
                pending_alloc = last_imm[_norm(size_reg)]
            continue
        m_imm = _MOV_IMM.match(text)
        if m_imm:
            value = int(m_imm[1], 16)
            reg = _norm(m_imm[2])
            if reg == _LENGTH_REG.get(callee) and value > 1:
                # 逆向切片语义：最靠近调用点的长度寄存器赋值获胜
                # （mmap 的 prot=edx 等中间赋值会被更近的 read 长度覆盖）
                length = value
                length_evidence = f"mov ${value:#x},%{m_imm[2]} @0x{insn['address']:x}"
            if value > 0:
                last_imm[reg] = value
            stack_tags.pop(reg, None)
            alloc_regs.pop(reg, None)
            continue
        m_lea = _LEA_STACK_OFF.match(text)
        if m_lea:
            offset = int(m_lea[1], 16)
            if offset < 0:
                stack_tags[_norm(m_lea[2])] = -offset
            continue
        m_rax = _MOV_RAX_TO.match(text)
        if m_rax:
            dst = _norm(m_rax[1])
            if pending_alloc is not None:
                alloc_regs[dst] = pending_alloc
                pending_alloc = None
                stack_tags.pop(dst, None)
            else:
                # rax 承接窗口内的 lea/拷贝结果（如 lea buf(%rbp),%rax → %rsi）
                if "rax" in stack_tags:
                    stack_tags[dst] = stack_tags["rax"]
                if "rax" in alloc_regs:
                    alloc_regs[dst] = alloc_regs["rax"]
            continue
        m_rr = _MOV_REG_REG.match(text)
        if m_rr:
            src, dst = _norm(m_rr[1]), _norm(m_rr[2])
            if src in stack_tags:
                stack_tags[dst] = stack_tags[src]
            if src in alloc_regs:
                alloc_regs[dst] = alloc_regs[src]
            continue
    dest_reg = _DEST_REG.get(callee, "rdi")
    if dest_reg in stack_tags:
        dest = {"kind": "stack", "offset": stack_tags[dest_reg]}
        dest_evidence = f"lea -{stack_tags[dest_reg]:#x}(%rbp) → %{dest_reg}"
    elif dest_reg in alloc_regs:
        dest = {"kind": "alloc", "size": alloc_regs[dest_reg]}
        dest_evidence = f"%{dest_reg} ← mmap/malloc 返回（尺寸 {alloc_regs[dest_reg]:#x}）"
    else:
        dest = None
        dest_evidence = ""
    if callee in _UNBOUNDED:
        length = None
        length_evidence = "gets 无长度参数（无界输入）"
    return {"length": length, "length_evidence": length_evidence,
            "dest": dest, "dest_evidence": dest_evidence,
            "canary_offset": canary}


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
        if dest:
            return {"verdict": "overflow_confirmed",
                    "reason": "gets 无界输入写入堆缓冲", "evidence": evidence}
        return {"verdict": "unknown_buffer", "reason": "目的缓冲不可解析",
                "evidence": evidence}
    if length is None:
        return {"verdict": "unknown_length", "reason": "长度来源非常量（寄存器/变量）",
                "evidence": evidence}
    if dest is None:
        return {"verdict": "unknown_buffer", "reason": "目的缓冲不可解析（长度已知）",
                "evidence": evidence}
    if dest["kind"] == "alloc":
        bound = dest["size"]
        if length > bound:
            return {"verdict": "overflow_confirmed",
                    "reason": f"长度 {length:#x} > 分配尺寸 {bound:#x}",
                    "bound": bound, "evidence": evidence}
        return {"verdict": "within_bound",
                "reason": f"长度 {length:#x} ≤ 分配尺寸 {bound:#x}（mmap/malloc 同尺寸）",
                "bound": bound, "evidence": evidence}
    bound = dest["offset"] - (8 if resolved.get("canary_offset") is not None else 0)
    if length > bound:
        return {"verdict": "overflow_confirmed",
                "reason": (f"长度 {length:#x} > 栈缓冲可用 {bound:#x}"
                           f"（rbp-{dest['offset']:#x}"
                           f"{'，含 canary' if resolved.get('canary_offset') is not None else ''}）"),
                "bound": bound, "evidence": evidence}
    return {"verdict": "within_bound",
            "reason": f"长度 {length:#x} ≤ 栈缓冲可用 {bound:#x}",
            "bound": bound, "evidence": evidence}


def scan_functions(functions: list[dict]) -> list[dict]:
    """对已解析的函数列表扫描全部输入调用点（纯函数，便于单测）。"""
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
            if callee not in ("read", "fgets", "gets"):
                continue
            resolved = _resolve_site(lines, index, callee)
            verdict = _verdict(callee, resolved)
            points.append({
                "function": str(fn.get("name")),
                "vaddr": f"0x{insn['address']:x}",
                "callee": callee,
                **verdict,
                "length": resolved.get("length"),
                "buffer": resolved.get("dest"),
            })
    order = {"overflow_confirmed": 0, "unbounded_input": 1,
             "unknown_length": 2, "unknown_buffer": 3, "within_bound": 4}
    points.sort(key=lambda p: (order.get(p["verdict"], 9), p["vaddr"]))
    return points


def scan_vuln_points(binary, runner, *, functions: list[dict] | None = None) -> dict:
    """扫描目标 ELF 的全部输入调用点（缺 functions 时自行 objdump）。"""
    if functions is None:
        result = runner.run_tool("objdump", ["-d", "--", runner.to_wsl_path(binary)])
        if not result.ok:
            raise ValueError(f"objdump 失败: {result.combined_output()[:120]}")
        from pwncraft.core.code_analysis import parse_disassembly
        functions = parse_disassembly(result.stdout)["functions"]
    points = scan_functions(functions)
    confirmed = sum(1 for p in points
                    if p["verdict"] in ("overflow_confirmed", "unbounded_input"))
    return {"binary": str(binary), "points": points,
            "confirmed": confirmed, "total": len(points)}
