"""x86-64 (AT&T objdump) linear dataflow tracer → CallSiteIR (VNext.2 M2.1/M2.2).

Instruction semantics live HERE (BinaryIR layer). Behavior recognizers
consume CallSiteIR/ObjectRef — they never re-read machine instructions.

Scope (deterministic, deliberately small):
  * per-function linear scan over objdump -d AT&T text;
  * System V AMD64 argument registers (rdi,rsi,rdx,rcx,r8,r9) and rax result;
  * mov / lea / cdqe / cltq / xor reg,reg / add-sub on values (const-fold
    when possible, else EXPR);
  * memory operands: off(base), abs(,idx,scale), off(base,idx,scale);
  * `call <sym@plt>` → CallSiteIR; result → rax = CALL_RESULT.

Not implemented (by design): full CFG, loops unrolling, aliases beyond a
single live value per register/slot. Anything unresolved → UNKNOWN.
"""
from __future__ import annotations

import re
from pathlib import Path

from pwnbao.core.value_ir import (
    CallSiteIR, K_ARG, K_CONST, K_EXPR, K_GLOBAL, K_LOAD, K_CALL_RESULT,
    K_STACK, K_UNKNOWN, ObjectRef, StoreIR, ValueIR,
)

_FUNCS_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
_LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t(\S+)\s*(.*)$")
_MEM_RE = re.compile(r"^(?:(-?0x[0-9a-f]+))?(?:\((%[a-z0-9]+)?(?:,(/?)?(%[a-z0-9]+))?(?:,([0-9]+))?\))?$")
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
_R64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi",
        "edi": "rdi", "esp": "rsp", "ebp": "rbp",
        "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
        "sil": "rsi", "dil": "rdi"}
UNKNOWN = ValueIR(kind=K_UNKNOWN, reason="unresolvable in linear pass")


def canonical_reg(reg: str) -> str:
    reg = reg.lstrip("%").lower()
    return _R64.get(reg, reg)


def parse_memory_operand(text: str) -> dict:
    """AT&T `disp(base,index,scale)` / `abs(,idx,scale)` / `-0x18(%rbp)`."""
    m = _MEM_RE.match(text.strip())
    if not m:
        return {}
    disp_s, base, _slash, index, scale = m.groups()
    return {"disp": int(disp_s, 16) if disp_s else 0,
            "base": base.lstrip("%") if base else "",
            "index": index.lstrip("%") if index else "",
            "scale": int(scale) if scale else 1,
            "abs_only": bool(disp_s and not base and not index)}


class _FuncState:
    def __init__(self, name: str) -> None:
        self.name = name
        self.regs: dict[str, ValueIR] = {}

    def get(self, reg: str) -> ValueIR:
        return self.regs.get(canonical_reg(reg), UNKNOWN)

    def set(self, reg: str, value: ValueIR) -> None:
        self.regs[canonical_reg(reg)] = value


def _const(text: str) -> ValueIR | None:
    t = text.strip().lstrip("$")
    try:
        return ValueIR(kind=K_CONST, value=int(t, 16) if t.startswith(("0x", "-0x")) else int(t))
    except ValueError:
        return None


def _load_from_operand(mem: dict, state: "_FuncState") -> ValueIR:
    """Resolve a memory *read* operand to a ValueIR."""
    if not mem:
        return UNKNOWN  # segment regs (%fs:0x28 canary), unparseable forms
    index_v = state.get(mem["index"]) if mem["index"] else None
    base_v = state.get(mem["base"]) if mem["base"] else None
    if mem["index"] and not mem["base"] and not mem["disp"]:
        return UNKNOWN
    if mem.get("abs_only"):
        return ValueIR(kind=K_GLOBAL, address=hex(mem["disp"]))
    if mem["index"] and (mem["disp"] or mem["base"]):
        # table-style: disp as GLOBAL base, index from register
        base = (ValueIR(kind=K_GLOBAL, address=hex(mem["disp"]))
                if mem["disp"] and not mem["base"]
                else base_v or UNKNOWN)
        return ValueIR(kind=K_LOAD, base=base,
                       index=index_v or UNKNOWN, scale=mem["scale"])
    if mem["base"] and mem["index"]:
        return ValueIR(kind=K_LOAD, base=base_v or UNKNOWN,
                       index=index_v or UNKNOWN, scale=mem["scale"],
                       offset=mem["disp"])
    if mem["base"]:
        off = mem["disp"]
        if off < 0 or mem["base"] in ("rbp", "ebp"):
            return ValueIR(kind=K_STACK, offset=off)
        base_val = base_v if base_v and base_v.kind != K_UNKNOWN else UNKNOWN
        return ValueIR(kind=K_LOAD, base=base_val, index=None, scale=1, offset=off)
    if mem["disp"]:  # absolute address read
        return ValueIR(kind=K_GLOBAL, address=hex(mem["disp"]))
    return UNKNOWN


def _slot_objectref(target: ValueIR) -> ObjectRef | None:
    """M2.3: normalize a slot reference to an ObjectRef.
    Direct: GLOBAL[index*scale] (scale 4/8) — the table slot itself.
    Field:  LOAD(slot, off=F) — a field (e.g. ->content) of that slot's
    struct; identity stays (table, index, scale) with the offset recorded
    by the caller via target.describe(), because the slot is what unifies
    free/edit/show across helpers."""
    if target.kind != K_LOAD or not target.base:
        return None
    if target.base.kind == K_GLOBAL:
        if target.scale in (4, 8) and target.index is not None:
            return ObjectRef(base=target.base.address,
                             index_key=target.index.index_key(),
                             scale=target.scale)
        return None
    if target.base.kind == K_LOAD and target.base.base and             target.base.base.kind == K_GLOBAL and target.base.scale in (4, 8):
        # one deref into the slot's struct (chunks[idx]->content)
        return ObjectRef(base=target.base.base.address,
                         index_key=target.base.index.index_key()
                         if target.base.index else "UNKNOWN",
                         scale=target.base.scale)
    return None


def split_operands(operands: str) -> tuple[str, str]:
    """Split 'src,dst' at the TOP-LEVEL comma (memory operands contain
    commas inside parentheses: 0x6020a0(,%rax,8),%rax)."""
    depth = 0
    for i, ch in enumerate(operands):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            return operands[:i].strip(), operands[i + 1:].strip()
    return operands.strip(), ""


def trace_stack_layouts(objdump_text: str) -> list[dict]:
    """M3 栈首期: 逐函数栈布局记录 (确定性)。

    slots: rbp 相对写入的槽位 (offset/size/kind), canary 由
    `mov %fs:0x28,%rax` + 相邻槽位写入识别; frame = sub $N,%rsp。
    """
    layouts: list[dict] = []
    state: _FuncState | None = None
    func = ""
    slots: dict[int, dict] = {}
    frame = 0
    canary_src = False
    for raw in objdump_text.splitlines():
        header = _FUNCS_RE.match(raw.strip())
        if header:
            if state is not None and slots:
                layouts.append({"function": func, "frame_size": frame,
                                "slots": sorted(slots.values(),
                                                key=lambda x: x["offset"])})
            func = header.group(2)
            state = _FuncState(func)
            slots, frame, canary_src = {}, 0, False
            continue
        line = _LINE_RE.match(raw.rstrip())
        if not line or state is None:
            continue
        addr, mnem, operands = line.groups()
        if mnem == "sub":
            parts = operands.split(",", 1)
            if len(parts) == 2 and parts[1].strip().lstrip("%") in ("rsp", "esp"):
                try:
                    frame = int(parts[0].strip().lstrip("$"), 16)
                except ValueError:
                    frame = 0
            continue
        if mnem.startswith("mov"):
            parts = operands.split(",", 1)
            if len(parts) != 2:
                continue
            src_s, dst_s = parts[0].strip(), parts[1].strip()
            if "fs:" in src_s:
                canary_src = True
                continue
            if dst_s.startswith("-") or ("(%rbp)" in dst_s and dst_s.startswith("-")):
                m = re.match(r"^(-?0x[0-9a-f]+)?\(%(\w+)\)$", dst_s)
                if m and m.group(2) in ("rbp", "ebp"):
                    off = int(m.group(1), 16) if m.group(1) else 0
                    # F08: 位宽由寄存器宽度推断, 非 mnemonic 后缀
                    # mov %eax → 4 bytes, mov %rax → 8 bytes, mov %al → 1 byte
                    reg_width = {"eax": 4, "ax": 2, "al": 1,
                                 "ebx": 4, "bx": 2, "bl": 1,
                                 "ecx": 4, "cx": 2, "cl": 1,
                                 "edx": 4, "dx": 2, "dl": 1,
                                 "esi": 4, "si": 2, "edi": 4, "di": 2,
                                 "rsp": 8, "rbp": 8,
                                 "r8d": 4, "r8": 8, "r9d": 4, "r9": 8,
                                 "r10d": 4, "r10": 8, "r11d": 4, "r11": 8,
                                 "r12d": 4, "r12": 8, "r13d": 4, "r13": 8,
                                 "r14d": 4, "r14": 8, "r15d": 4, "r15": 8,
                                 }.get(src_s.lstrip("%").strip(), 8)
                    size = reg_width
                    kind = "canary" if canary_src else ("data" if size == 8 else "data")
                    prev = slots.get(off)
                    if prev and prev["kind"] == "canary":
                        kind = "canary"
                    slots[off] = {"offset": off, "size": size, "kind": kind}
                canary_src = False
            continue
        if mnem in ("leave", "ret"):
            continue
    if slots:
        layouts.append({"function": func, "frame_size": frame,
                        "slots": sorted(slots.values(), key=lambda x: x["offset"])})
    return layouts


def trace_callsites(objdump_text: str) -> list[CallSiteIR]:
    """Extract per-callsite argument ValueIRs from AT&T objdump text."""
    sites: list[CallSiteIR] = []
    stores: list[StoreIR] = []
    state: _FuncState | None = None
    func = ""
    for raw in objdump_text.splitlines():
        header = _FUNCS_RE.match(raw.strip())
        if header:
            func = header.group(2)
            state = _FuncState(func)
            continue
        line = _LINE_RE.match(raw.rstrip())
        if not line or state is None:
            continue
        addr, mnem, operands = line.groups()
        operands = operands.strip()
        src_s, dst_s = split_operands(operands)
        # -- call
        if mnem == "call":
            m = re.search(r"<([^>]+)>", operands)
            callee = m.group(1) if m else operands
            callee = callee.replace("@plt", "")
            args = tuple(state.get(r) for r in _ARG_REGS)
            # trim trailing UNKNOWNs
            while args and args[-1].kind == K_UNKNOWN:
                args = args[:-1]
            sites.append(CallSiteIR(
                address=f"0x{addr}", function=func, callee=callee,
                args=args, result=ValueIR(kind=K_CALL_RESULT, callee=callee,
                                          site=f"0x{addr}"),
                span_start=f"0x{addr}", span_end=f"0x{addr}"))
            state.set("rax", sites[-1].result)
            continue
        # -- value ops
        if mnem in ("mov", "movq", "movl", "movb", "movw", "lea", "movabs"):
            src_v = None
            if src_s.startswith("$"):
                src_v = _const(src_s)
            elif "(" in src_s:
                mem = parse_memory_operand(src_s)
                src_v = _load_from_operand(mem, state)
            else:
                src_v = state.get(src_s)
            if src_v is None:
                src_v = UNKNOWN
            if mnem == "lea" and "(" in dst_s:
                # address computation: lea mem → treat as EXPR over components
                mem = parse_memory_operand(dst_s)
                if mem["index"] and mem["scale"] in (4, 8) and (mem["disp"] or mem["base"]):
                    base = (ValueIR(kind=K_GLOBAL, address=hex(mem["disp"]))
                            if mem["disp"] and not mem["base"]
                            else state.get(mem["base"]) if mem["base"] else UNKNOWN)
                    index = state.get(mem["index"]) if mem["index"] else None
                    src_v = ValueIR(kind=K_LOAD, base=base or UNKNOWN,
                                    index=index or UNKNOWN, scale=mem["scale"],
                                    offset=mem["disp"])
                elif mem["base"] and not mem["index"]:
                    src_v = state.get(mem["base"]) if mem["base"] else UNKNOWN
            dst_mem = "(" in dst_s
            if dst_mem:
                mem = parse_memory_operand(dst_s)
                if not mem:
                    continue  # segment-relative or exotic store: skip env update
                target = _load_from_operand(mem, state)
                slot = _slot_objectref(target)
                stores.append(StoreIR(
                    address=f"0x{addr}", function=func, slot=slot,
                    target=target, value=src_v, line_address=f"0x{addr}"))
                continue  # memory writes don't update register env
            dst_reg = canonical_reg(dst_s)
            state.set(dst_reg, src_v)
            if dst_reg in _ARG_REGS[:len(_ARG_REGS)]:
                pass
            continue
        if mnem in ("cdqe", "cltq"):
            state.set("rax", state.get("eax"))
            continue
        if mnem == "xor" and src_s == dst_s:
            state.set(dst_s, ValueIR(kind=K_CONST, value=0))
            continue
        if mnem in ("add", "sub") and dst_s and not dst_s.startswith("$"):
            rhs = _const(src_s)
            lhs = state.get(dst_s)
            if rhs is not None and lhs.kind == K_CONST:
                delta = rhs.value if mnem == "add" else -rhs.value
                state.set(dst_s, ValueIR(kind=K_CONST, value=(lhs.value or 0) + delta))
            elif rhs is not None:
                state.set(dst_s, ValueIR(kind=K_EXPR, op=mnem,
                                         operands=(lhs, rhs)))
            continue
        if mnem in ("test", "cmp", "jne", "je", "jle", "jge", "js", "jns",
                    "jmp", "jle", "jae", "jbe", "push", "pop", "ret", "nop",
                    "endbr64", "leave", "cs", "nopw", "nopl", "data16"):
            if mnem in ("push", "pop") and dst_s and "(" not in dst_s:
                continue
            continue
        # mov %fs:0x28 style / others: leave env untouched
        continue
    return sites
