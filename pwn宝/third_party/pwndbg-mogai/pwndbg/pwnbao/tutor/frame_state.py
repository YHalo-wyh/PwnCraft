from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


_CALL_PROTOTYPES = {
    "malloc": (("rdi", "size"),),
    "calloc": (("rdi", "nmemb"), ("rsi", "size")),
    "realloc": (("rdi", "old_ptr"), ("rsi", "size")),
    "free": (("rdi", "ptr"),),
    "read": (("rdi", "fd"), ("rsi", "buf"), ("rdx", "count")),
    "write": (("rdi", "fd"), ("rsi", "buf"), ("rdx", "count")),
    "recv": (("rdi", "fd"), ("rsi", "buf"), ("rdx", "count")),
    "memcpy": (("rdi", "dst"), ("rsi", "src"), ("rdx", "n")),
    "memmove": (("rdi", "dst"), ("rsi", "src"), ("rdx", "n")),
}


@dataclass(frozen=True)
class FramePointerEvidence:
    confirmed: bool
    saved_rbp: int | None = None
    saved_rip: int | None = None
    saved_rbp_slot: int | None = None
    saved_rip_slot: int | None = None
    reason: str = "GDB DWARF/CFI unwind"


def _int_register(frame, name: str) -> int | None:
    try:
        return int(frame.read_register(name))
    except Exception:
        return None


def _read_pointer(address: int, pointer_size: int = 8) -> int | None:
    import gdb

    try:
        data = bytes(gdb.selected_inferior().read_memory(address, pointer_size))
        return int.from_bytes(data, "little")
    except Exception:
        return None


def _symbol(address: int | None) -> str:
    if address is None:
        return "UNKNOWN"
    import gdb

    try:
        text = gdb.execute(f"info symbol {address:#x}", to_string=True).strip()
        if text and not text.startswith("No symbol"):
            return text.split(" in section", 1)[0]
    except Exception:
        pass
    return "UNKNOWN"


def _module(address: int | None) -> str:
    if address is None:
        return "UNKNOWN"
    import gdb

    try:
        shared = gdb.solib_name(address)
        if shared:
            return shared.rsplit("/", 1)[-1]
        filename = gdb.current_progspace().filename
        if filename:
            return filename.rsplit("/", 1)[-1]
    except Exception:
        pass
    return "UNKNOWN"


def _source(frame) -> str:
    try:
        sal = frame.find_sal()
        if sal and sal.symtab:
            return f"{sal.symtab.filename}:{sal.line}"
    except Exception:
        pass
    return "\u4e0d\u53ef\u7528"


def _frame_level(frame) -> int:
    level = 0
    current = frame
    while current is not None:
        try:
            current = current.newer()
        except Exception:
            break
        if current is not None:
            level += 1
    return level


def _frame_pointer_evidence(frame, older, rsp: int | None, rbp: int | None) -> FramePointerEvidence:
    if older is None or rsp is None or rbp is None:
        return FramePointerEvidence(False, reason="\u7f3a\u5c11 caller \u6216\u5bc4\u5b58\u5668\u8bc1\u636e")
    if rbp % 8 or not (rsp <= rbp < rsp + 0x100000):
        return FramePointerEvidence(False, reason="RBP \u4e0d\u5728\u5f53\u524d\u53ef\u4fe1 stack frame \u8303\u56f4")
    saved_rbp = _read_pointer(rbp)
    saved_rip = _read_pointer(rbp + 8)
    older_rbp = _int_register(older, "rbp")
    try:
        older_pc = int(older.pc())
    except Exception:
        older_pc = None
    if saved_rbp is None or saved_rip is None or older_pc is None:
        return FramePointerEvidence(False, reason="\u65e0\u6cd5\u8bfb\u53d6/\u6838\u5bf9 RBP frame slots")
    # Both links must agree with GDB's independent unwinder.  A merely
    # stack-looking RBP is not sufficient evidence.
    if saved_rip != older_pc or (older_rbp is not None and saved_rbp != older_rbp):
        return FramePointerEvidence(False, reason="RBP slots \u4e0e GDB unwinder \u4e0d\u4e00\u81f4")
    return FramePointerEvidence(True, saved_rbp, saved_rip, rbp, rbp + 8, "RBP slots + GDB unwinder \u4e00\u81f4")


def _current_instruction() -> str:
    import gdb

    try:
        return gdb.execute("x/i $pc", to_string=True).strip()
    except Exception:
        return "UNKNOWN"


def _current_call(frame, instruction: str) -> dict[str, Any] | None:
    match = re.search(r"\bcall\w*\s+(?:0x[0-9a-f]+\s+)?<([^>@+]+)", instruction, re.I)
    if not match:
        if re.search(r"\bcall\w*\s+[*%]?[a-z][a-z0-9]*\b", instruction, re.I):
            return {"target": "UNKNOWN", "arguments": [], "provenance": "UNKNOWN"}
        return None
    target = match.group(1).split("@", 1)[0]
    prototype = _CALL_PROTOTYPES.get(target)
    if prototype is None:
        return {"target": target, "arguments": [], "provenance": "GDB_SYMBOL"}
    arguments = []
    for register, meaning in prototype:
        arguments.append({
            "register": register.upper(),
            "meaning": meaning,
            "value": _int_register(frame, register),
            "provenance": "ABI_DERIVED",
        })
    return {"target": target, "arguments": arguments, "provenance": "GDB_SYMBOL+ABI_DERIVED"}


def inspect_frame(frame=None) -> dict[str, Any]:
    import gdb

    frame = frame or gdb.selected_frame()
    older = frame.older()
    pc = int(frame.pc())
    rsp = _int_register(frame, "rsp")
    rbp = _int_register(frame, "rbp")
    evidence = _frame_pointer_evidence(frame, older, rsp, rbp)
    older_pc = int(older.pc()) if older is not None else None
    instruction = _current_instruction()
    registers = {}
    for register, label in (
        ("rdi", "arg1"), ("rsi", "arg2"), ("rdx", "arg3"),
        ("rcx", "arg4"), ("r8", "arg5"), ("r9", "arg6"),
        ("rax", "return/value"), ("rsp", "stack top"),
        ("rbp", "帧指针" if evidence.confirmed else "通用寄存器"),
        ("rip", "current instruction"),
    ):
        registers[register.upper()] = {
            "value": _int_register(frame, register),
            "label": label,
            "provenance": "GDB_UNWIND" if register in {"rsp", "rbp", "rip"} else "OBSERVED",
        }
    return {
        "level": _frame_level(frame),
        "function": frame.name() or "UNKNOWN",
        "pc": pc,
        "pc_symbol": _symbol(pc),
        "module": _module(pc),
        "source": _source(frame),
        "instruction": instruction,
        "caller": older.name() if older is not None and older.name() else "UNKNOWN",
        "caller_pc": older_pc,
        "caller_symbol": _symbol(older_pc),
        "rsp": rsp,
        "rbp": rbp,
        "rbp_role": "frame_pointer" if evidence.confirmed else "general_register",
        "frame_recovery": evidence.reason,
        "saved_rbp": evidence.saved_rbp,
        "saved_rip": evidence.saved_rip,
        "saved_rbp_slot": evidence.saved_rbp_slot,
        "saved_rip_slot": evidence.saved_rip_slot,
        "return_target": older_pc,
        "return_symbol": _symbol(older_pc),
        "registers": registers,
        "current_call": _current_call(frame, instruction),
        "provenance": "GDB_UNWIND",
    }


def inspect_frames(limit: int = 32) -> list[dict[str, Any]]:
    import gdb

    result = []
    frame = gdb.newest_frame()
    while frame is not None and len(result) < max(1, limit):
        try:
            pc = int(frame.pc())
            result.append({
                "level": len(result),
                "function": frame.name() or "UNKNOWN",
                "pc": pc,
                "symbol": _symbol(pc),
                "module": _module(pc),
                "source": _source(frame),
                "provenance": "GDB_UNWIND",
            })
            frame = frame.older()
        except Exception:
            break
    return result


def format_address(value: int | None) -> str:
    return "UNKNOWN" if value is None else f"{value:#x}"


def render_frame(state: dict[str, Any]) -> str:
    rbp_role = "帧指针" if state["rbp_role"] == "frame_pointer" else "通用寄存器"
    lines = [
        "\u2500\u2500 FRAME \u5f53\u524d\u6808\u5e27 \u2500\u2500",
        f"#{state['level']} {state['function']}",
        f"\u5f53\u524d PC  {format_address(state['pc'])} <{state['pc_symbol']}>",
        f"Caller   {state['caller']}  {format_address(state['caller_pc'])} <{state['caller_symbol']}>",
        f"RSP      {format_address(state['rsp'])}",
        f"RBP      {format_address(state['rbp'])}",
        f"RBP \u89d2\u8272 {rbp_role}",
        f"\u8fd4\u56de\u76ee\u6807 {format_address(state['return_target'])} <{state['return_symbol']}>",
        f"\u6062\u590d\u6765\u6e90 {state['frame_recovery']}",
    ]
    return "\n".join(lines) + "\n"


def render_current(state: dict[str, Any]) -> str:
    lines = [
        "\u2500\u2500 CURRENT \u5f53\u524d\u6267\u884c\u4f4d\u7f6e \u2500\u2500",
        f"#{state['level']} {state['function']}  {format_address(state['pc'])}",
        f"\u6a21\u5757 {state['module']}  \u6e90\u7801 {state['source']}",
        f"\u6307\u4ee4 {state['instruction']}",
        f"Caller {state['caller_symbol']}",
        f"RSP {format_address(state['rsp'])}  RBP {'frame' if state['rbp_role'] == 'frame_pointer' else 'general'}",
    ]
    call = state.get("current_call")
    if call:
        lines.append(f"\u5f53\u524d call target: {call['target']}")
        for item in call["arguments"]:
            lines.append(f"  {item['register']}={format_address(item['value'])}  {item['meaning']}")
    return "\n".join(lines) + "\n"
