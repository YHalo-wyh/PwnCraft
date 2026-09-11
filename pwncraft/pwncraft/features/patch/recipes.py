"""一键通防手法：PLT 劫持、read/fgets 长度收紧、函数 NOP / ret 化、自定义字节。

全部手法输出 PatchOp 列表（先预览后应用），只做等长替换，不改文件大小。
函数与 PLT 信息来自 code_analysis 的 objdump 真值，本模块不做无依据猜测。
"""
from __future__ import annotations

import re
import struct

from pwncraft.core.syscalls import normalize_architecture
from .patch_core import PatchLab, PatchOp, find_code_cave, parse_instruction_lines, rel32_jmp

_CALL_PLT_RE = re.compile(r"^\s*call[qw]?\s+([0-9a-fA-F]+)\s+<([^>]+)>")
_MOV_IMM32_RE = re.compile(r"^\s*mov[q]?\s+\$0x([0-9a-fA-F]+),%(e?(?:dx|si|di|cx|ax))\b")
_PUSH_IMM_RE = re.compile(r"^\s*push[l]?\s+\$0x([0-9a-fA-F]+)\b")

# 长度收紧支持的调用。amd64 用长度参数的 imm32 载体寄存器：
# read/recv/recvfrom 的长度是第 3 参数（edx），fgets 的尺寸是第 2 参数（esi）。
LENGTH_REGISTERS = {
    "read": "edx",
    "recv": "edx",
    "recvfrom": "edx",
    "fgets": "esi",
}
# i386 cdecl 下长度参数的实参序号（0 起），用于从 call 向前回溯 push 立即数。
LENGTH_ARG_INDEX = {"read": 2, "recv": 2, "recvfrom": 2, "fgets": 1}
_LENGTH_CALLEES = tuple(LENGTH_REGISTERS)
_MOV_OPCODE = {  # mov r32, imm32 的操作码（rd 编码）
    "eax": 0xB8, "ecx": 0xB9, "edx": 0xBA, "ebx": 0xBB,
    "esp": 0xBC, "ebp": 0xBD, "esi": 0xBE, "edi": 0xBF,
}


_PLT_SECTIONS = (".plt", ".plt.sec")


def extract_plt_stubs(functions: list[dict]) -> dict[str, dict]:
    """从 code_analysis 函数列表提取 PLT stub（名 → 地址/大小）。

    新旧两种 objdump 布局都要认：传统布局每个 `xxx@plt` 在 `.plt`；
    IBT/endbr64 布局的入口 stub 在 `.plt.sec`，`.plt` 只剩一整块解析桩
    （名为 `.plt`，不以 @plt 结尾，跳过）。
    """
    stubs: dict[str, dict] = {}
    for fn in functions:
        if str(fn.get("section") or "") not in _PLT_SECTIONS:
            continue
        raw_name = str(fn["name"])
        if not raw_name.endswith("@plt"):
            continue
        instructions = parse_instruction_lines(fn.get("assembly") or "")
        if not instructions:
            continue
        start = int(fn["address"], 16) if isinstance(fn["address"], str) else int(fn["address"])
        end = instructions[-1]["address"] + instructions[-1]["size"]
        name = raw_name[: -len("@plt")]
        stubs[name] = {"name": name, "address": start, "size": end - start,
                       "raw_name": raw_name}
    return stubs


def find_call_sites(functions: list[dict], target: str) -> list[dict]:
    """所有 `call <target@plt>` / `call <target>` 调用点（函数名 + 指令）。"""
    sites: list[dict] = []
    wanted = {f"{target}@plt", target}
    for fn in functions:
        for insn in parse_instruction_lines(fn.get("assembly") or ""):
            match = _CALL_PLT_RE.match(insn["text"] or "")
            if match and match[2] in wanted:
                sites.append({"function": str(fn["name"]), "insn": insn})
    return sites


def build_plt_call_redirect(lab: PatchLab, functions: list[dict], source: str,
                            target: str, *, function: str = "", vaddr: int | None = None) -> dict:
    """把所有 `call source@plt` 的 rel32 重定向到 target@plt（V1ct0r 手法）。"""
    stubs = extract_plt_stubs(functions)
    if source not in stubs:
        raise ValueError(f"PLT 里没有 {source}@plt（可用: {', '.join(sorted(stubs)) or '无'}）")
    if target not in stubs:
        raise ValueError(f"PLT 里没有 {target}@plt（可用: {', '.join(sorted(stubs)) or '无'}）")
    sites = find_call_sites(functions, source)
    if function:
        sites = [site for site in sites if site["function"] == function]
    if vaddr is not None:
        sites = [site for site in sites if site["insn"]["address"] == vaddr]
    if not sites:
        raise ValueError(f"反汇编中没有发现对 {source}@plt 的调用点")
    ops: list[PatchOp] = []
    for site in sites:
        insn = site["insn"]
        if insn["bytes"][0] != 0xE8 or insn["size"] != 5:
            raise ValueError(
                f"0x{insn['address']:x} 的调用不是 5 字节 call rel32，无法重定向")
        new_rel = stubs[target]["address"] - (insn["address"] + 5)
        original = lab.read_at(insn["address"], 5)
        if original != insn["bytes"]:
            raise ValueError(f"0x{insn['address']:x} 处磁盘字节与反汇编不一致，文件已被修改")
        ops.append(PatchOp(
            kind="plt_call", vaddr=insn["address"], file_offset=lab.offset_of(insn["address"]),
            original_bytes=original,
            new_bytes=b"\xe8" + struct.pack("<i", new_rel),
            note=f"{site['function']}: call {source}@plt → call {target}@plt"))
    return {"ops": ops, "warnings": [f"共改写 {len(ops)} 处调用点；目标函数签名不同可能需要人工确认参数语义。"]}


def build_plt_stub_redirect(lab: PatchLab, functions: list[dict], source: str,
                            target: str) -> dict:
    """把 `source@plt` stub 整体重写为跳向 `target@plt`（全局生效）。"""
    stubs = extract_plt_stubs(functions)
    for name in (source, target):
        if name not in stubs:
            raise ValueError(f"PLT 里没有 {name}@plt（可用: {', '.join(sorted(stubs)) or '无'}）")
    src, dst = stubs[source], stubs[target]
    if src["size"] < 5:
        raise ValueError(f"{source}@plt stub 小于 5 字节，无法写入跳转")
    original = lab.read_at(src["address"], src["size"])
    jump = b"\xe9" + struct.pack("<i", dst["address"] - (src["address"] + 5))
    new_bytes = jump + b"\x90" * (src["size"] - 5)
    return {"ops": [PatchOp(kind="plt_stub", vaddr=src["address"],
                            file_offset=lab.offset_of(src["address"]),
                            original_bytes=original, new_bytes=new_bytes,
                            note=f"{source}@plt → jmp {target}@plt（其余字节 NOP）")],
            "warnings": ["PLT stub 级替换对该函数的所有调用全局生效，包括程序正常功能里的调用。"]}


def _function_instructions(functions: list[dict], name: str) -> tuple[dict, list[dict]]:
    fn = next((f for f in functions if str(f.get("name")) == name), None)
    if fn is None:
        raise ValueError(f"函数 {name!r} 不在当前反汇编列表中")
    instructions = parse_instruction_lines(fn.get("assembly") or "")
    if not instructions:
        raise ValueError(f"函数 {name!r} 没有可解析的指令行")
    return fn, instructions


def _calls_callee(text: str, callee: str) -> bool:
    match = _CALL_PLT_RE.match(text or "")
    return bool(match) and str(match[2]).startswith(f"{callee}@")


def _first_call_callee(instructions: list[dict]) -> str:
    """窗口内第一条直接调用的符号名（无符号间接调用不算），用于长度立即数归属判定。"""
    for insn in instructions:
        match = _CALL_PLT_RE.match(str(insn.get("text") or ""))
        if match:
            return str(match[2]).split("@", 1)[0]
    return ""


def instruction_region(functions: list[dict], function: str, start: int, end: int) -> list[dict]:
    """Resolve a contiguous span bounded by complete instructions in one function."""
    _, instructions = _function_instructions(functions, function)
    if not start < end or end - start > 0x10000:
        raise ValueError("请选择同一函数内 1–65536 字节的连续指令区间")
    selected = [i for i in instructions if start <= i["address"] < end]
    cursor = start
    for insn in selected:
        if insn["address"] != cursor:
            raise ValueError("选区不连续或起点不在指令边界，请刷新反汇编后重选")
        cursor += insn["size"]
    if not selected or cursor != end:
        raise ValueError("选区终点不在指令边界或越过当前函数，请重选完整指令")
    return selected


def build_instruction_patch(lab: PatchLab, functions: list[dict], function: str,
                            start: int, end: int, *, kind: str,
                            replacement: bytes | None = None, pad: bool = True) -> dict:
    selected = instruction_region(functions, function, start, end)
    original = b"".join(i["bytes"] for i in selected)
    if lab.read_at(start, len(original)) != original:
        raise ValueError("选中指令与磁盘字节不一致，请刷新反汇编")
    if kind == "nop_call":
        if len(selected) != 1 or not re.match(r"^(?:bnd\s+|notrack\s+)?call[qwl]?\s", selected[0]["text"]):
            raise ValueError("NOP 调用只接受一条 call 指令（直接或间接调用）")
    if replacement is None:
        replacement = b"\x90" * len(original)
    if len(replacement) > len(original):
        raise ValueError(f"新汇编需要 {len(replacement)} 字节，选区只有 {len(original)} 字节；请扩选完整指令")
    if len(replacement) < len(original):
        if not pad:
            raise ValueError("新汇编短于选区，请启用 NOP 填充或调整选区")
        replacement += b"\x90" * (len(original) - len(replacement))
    op = PatchOp(kind=kind, vaddr=start, file_offset=lab.offset_of(start),
                 original_bytes=original, new_bytes=replacement,
                 note=f"{function}: {kind} @0x{start:x}，{len(selected)} 条指令 / {len(original)} 字节")
    return {"ops": [op], "warnings": [
        "跳过调用后返回寄存器不会自动设置，请核对后续代码是否使用返回值。"
        if kind == "nop_call" else "修改限定在选中的完整指令区间；应用后请检查正常输入行为。"]}


def build_skip_call_result(lab: PatchLab, functions: list[dict], function: str,
                           start: int, end: int, value: int = 0) -> dict:
    """Skip exactly one call and synthesize its integer return value in EAX."""
    selected = instruction_region(functions, function, start, end)
    if len(selected) != 1 or not re.match(
            r"^(?:bnd\s+|notrack\s+)?call[qwl]?\s", selected[0]["text"]):
        raise ValueError("跳过调用并设返回值只接受一条 call 指令")
    raw = int(value)
    if not -(1 << 31) <= raw <= 0xFFFFFFFF:
        raise ValueError("调用返回值必须在 int32 / uint32 范围内")
    encoded = raw & 0xFFFFFFFF
    replacement = b"\x31\xc0" if encoded == 0 else b"\xb8" + struct.pack("<I", encoded)
    if len(replacement) > selected[0]["size"]:
        raise ValueError(
            f"该 call 只有 {selected[0]['size']} 字节，放不下固定返回值 0x{encoded:x}；可使用返回 0")
    built = build_instruction_patch(lab, functions, function, start, end,
                                    kind="skip_call_result", replacement=replacement, pad=True)
    built["warnings"] = ["调用的副作用会被跳过；EAX 固定为所选值，应用后需复核错误处理分支。"]
    return built


def build_code_cave_hook(lab: PatchLab, functions: list[dict], function: str,
                         start: int, end: int, assembly: str,
                         mode: str = "replace") -> dict:
    """Redirect a whole-instruction span to user assembly in an executable zero cave."""
    if mode not in {"replace", "before", "after"}:
        raise ValueError("跳板模式只支持 replace / before / after")
    selected = instruction_region(functions, function, start, end)
    original = b"".join(insn["bytes"] for insn in selected)
    if len(original) < 5:
        raise ValueError("code cave 跳板至少需要覆盖 5 字节完整指令")
    if lab.read_at(start, len(original)) != original:
        raise ValueError("选中指令与磁盘字节不一致，请刷新反汇编")
    if mode != "replace":
        unsafe = [insn for insn in selected if re.search(
            r"\(%rip\)|^(?:bnd\s+|notrack\s+)?(?:call|j[a-z]*|loop)[qwl]?\s",
            str(insn.get("text") or ""))]
        if unsafe:
            raise ValueError(
                f"{mode} 模式不能搬运 RIP 相对或控制流指令（首处 0x{unsafe[0]['address']:x}）；"
                "改用 replace 并在汇编中显式恢复所需语义")
    from .bytecode_catalog import assemble
    bits = 64 if lab.geometry()["is64"] else 32
    # First pass determines a conservative cave size; second pass fixes relative encodings.
    provisional = bytes.fromhex(assemble(assembly, bits=bits, vaddr=start)["bytes"])
    needed = len(provisional) + (len(original) if mode != "replace" else 0) + 5
    cave = find_code_cave(lab.binary, needed, geometry=lab.geometry())
    custom = bytes.fromhex(assemble(assembly, bits=bits, vaddr=cave["vaddr"])["bytes"])
    if len(custom) + (len(original) if mode != "replace" else 0) + 5 > cave["size"]:
        cave = find_code_cave(
            lab.binary, len(custom) + (len(original) if mode != "replace" else 0) + 5,
            geometry=lab.geometry())
        custom = bytes.fromhex(assemble(assembly, bits=bits, vaddr=cave["vaddr"])["bytes"])
    body = custom if mode == "replace" else (
        custom + original if mode == "before" else original + custom)
    jump_back_at = cave["vaddr"] + len(body)
    payload = body + rel32_jmp(jump_back_at, end)
    cave_original = lab.read(cave["offset"], len(payload))
    if cave_original.strip(b"\x00"):
        raise ValueError("code cave 不再是全零，文件已被外部修改")
    entry = rel32_jmp(start, cave["vaddr"]) + b"\x90" * (len(original) - 5)
    return {"ops": [
        PatchOp(kind="cave_hook", vaddr=start, file_offset=lab.offset_of(start),
                original_bytes=original, new_bytes=entry,
                note=f"{function}: 跳转 code cave 0x{cave['vaddr']:x}（{mode}）"),
        PatchOp(kind="cave_payload", vaddr=cave["vaddr"], file_offset=cave["offset"],
                original_bytes=cave_original, new_bytes=payload,
                note=f"自定义汇编 {len(custom)} 字节 + 回跳 0x{end:x}"),
    ], "warnings": [
        "自定义跳板不会自动保存寄存器、标志位或栈平衡；应用后必须运行正常业务与异常输入测试。",
        "before/after 只搬运无 RIP 相对和无控制流的原指令；replace 会删除所选原语义。",
    ], "cave": cave}


def build_read_length(lab: PatchLab, functions: list[dict], function: str,
                      callee: str, new_size: int, *, vaddr: int | None = None) -> dict:
    """收紧 read/recv/recvfrom/fgets 长度立即数（amd64 寄存器 / i386 栈传参）。"""
    if callee not in LENGTH_REGISTERS:
        raise ValueError(f"长度收紧支持 {' / '.join(_LENGTH_CALLEES)} 的常量长度")
    bits = 64 if lab.geometry()["is64"] else 32
    size = int(new_size)
    if not 0 < size <= 0xFFFFFFFF:
        raise ValueError("新长度超出 u32 范围")
    fn, instructions = _function_instructions(functions, function)
    ops: list[PatchOp] = []
    if bits == 64:
        register = LENGTH_REGISTERS[callee]
        for index, insn in enumerate(instructions):
            if vaddr is not None and insn["address"] != vaddr:
                continue
            match = _MOV_IMM32_RE.match(insn["text"] or "")
            if not match or match[2] != register or insn["size"] != 5:
                continue
            window = instructions[index + 1:index + 6]
            if _first_call_callee(window) != callee:
                continue
            if insn["bytes"][0] != _MOV_OPCODE[match[2]]:
                raise ValueError(f"0x{insn['address']:x} 处寄存器编码与预期不符，请人工确认")
            original = lab.read_at(insn["address"], 5)
            if original != insn["bytes"]:
                raise ValueError(f"0x{insn['address']:x} 处磁盘字节与反汇编不一致，文件已被修改")
            ops.append(PatchOp(
                kind="readlen", vaddr=insn["address"], file_offset=lab.offset_of(insn["address"]),
                original_bytes=original,
                new_bytes=bytes([_MOV_OPCODE[match[2]]]) + struct.pack("<I", size),
                note=f"{fn['name']}: mov {match[2]},0x{int(match[1],16):x} → 0x{size:x}（{callee} 长度）"))
    else:
        # cdecl：离 call 最近的 push 是第 1 参数；长度参数序号见 LENGTH_ARG_INDEX。
        arg_index = LENGTH_ARG_INDEX[callee]
        for call_index, call in enumerate(instructions):
            if not _calls_callee(call["text"], callee):
                continue
            pushes = []
            for candidate in reversed(instructions[max(0, call_index - 12):call_index]):
                text = str(candidate.get("text") or "").lstrip()
                if text.startswith("call"):
                    break
                if text.startswith("push"):
                    pushes.append(candidate)
            if len(pushes) <= arg_index:
                continue
            insn = pushes[arg_index]
            if vaddr is not None and insn["address"] != vaddr:
                continue
            match = _PUSH_IMM_RE.match(insn["text"] or "")
            if not match or insn["size"] not in (2, 5):
                continue
            original = lab.read_at(insn["address"], insn["size"])
            if original != insn["bytes"]:
                raise ValueError(f"0x{insn['address']:x} 处磁盘字节与反汇编不一致，文件已被修改")
            if original[0] == 0x68 and len(original) == 5:
                replacement = b"\x68" + struct.pack("<I", size)
            elif original[0] == 0x6A and len(original) == 2 and size <= 0x7F:
                replacement = bytes((0x6A, size))
            else:
                raise ValueError(f"0x{insn['address']:x} 处不是可安全等长改写的 push 立即数")
            ops.append(PatchOp(
                kind="readlen", vaddr=insn["address"], file_offset=lab.offset_of(insn["address"]),
                original_bytes=original, new_bytes=replacement,
                note=f"{fn['name']}: push 0x{int(match[1],16):x} → 0x{size:x}（{callee} 长度，第 {arg_index + 1} 参数）"))
    if not ops:
        raise ValueError(
            f"{function!r} 内未找到可证明流向 {callee}@plt 的长度立即数；"
            "可能长度来自寄存器或常量传播，请用手动字节 Patch")
    return {"ops": ops, "warnings": ["新长度应覆盖缓冲区实际容量（对照栈帧大小），过小会截断正常输入。"]}


def build_nop_function(lab: PatchLab, functions: list[dict], function: str) -> dict:
    """整个函数体用 0x90 填充（按反汇编指令边界）。"""
    fn, instructions = _function_instructions(functions, function)
    start = instructions[0]["address"]
    end = instructions[-1]["address"] + instructions[-1]["size"]
    original = lab.read_at(start, end - start)
    ops = [PatchOp(kind="nop_function", vaddr=start, file_offset=lab.offset_of(start),
                   original_bytes=original, new_bytes=b"\x90" * (end - start),
                   note=f"{fn['name']}: 整函数 NOP（{end - start} 字节）")]
    return {"ops": ops, "warnings": ["整函数 NOP 会移除 ret 和尾跳转，执行可能落入后续函数；若目的是跳过调用，请使用 NOP 单处调用或 ret 化。"]}


def build_ret_function(lab: PatchLab, functions: list[dict], function: str) -> dict:
    """函数首字节改为 0xC3（最小修改的“废函数”手法）。"""
    fn, instructions = _function_instructions(functions, function)
    start = instructions[0]["address"]
    original = lab.read_at(start, 1)
    ops = [PatchOp(kind="ret_function", vaddr=start, file_offset=lab.offset_of(start),
                   original_bytes=original, new_bytes=b"\xc3",
                   note=f"{fn['name']}: 首字节 → ret（返回值 eax 为调用前残留值）")]
    return {"ops": ops, "warnings": ["直接 ret 的返回值不可控；调用方若依赖返回值判断，需一并检查。"]}


def _prefix_region(instructions: list[dict], minimum: int) -> tuple[int, bytes]:
    """Return a whole-instruction function prefix large enough for a replacement."""
    selected: list[dict] = []
    size = 0
    for insn in instructions:
        selected.append(insn)
        size += insn["size"]
        if size >= minimum:
            break
    if size < minimum:
        raise ValueError(f"函数入口只有 {size} 字节，放不下 {minimum} 字节返回桩")
    return selected[0]["address"], b"".join(insn["bytes"] for insn in selected)


def build_return_constant(lab: PatchLab, functions: list[dict], function: str, value: int) -> dict:
    """Replace a function prefix with a deterministic EAX return value and ret."""
    fn, instructions = _function_instructions(functions, function)
    raw = int(value)
    if not -(1 << 31) <= raw <= 0xFFFFFFFF:
        raise ValueError("固定返回值必须在 int32 / uint32 范围内")
    encoded = raw & 0xFFFFFFFF
    if encoded == 0:
        stub = b"\x31\xc0\xc3"  # xor eax,eax; ret
    elif encoded == 0xFFFFFFFF:
        stub = b"\x83\xc8\xff\xc3"  # or eax,-1; ret
    else:
        stub = b"\xb8" + struct.pack("<I", encoded) + b"\xc3"
    preserve = b""
    body = instructions
    if instructions[0]["bytes"] == b"\xf3\x0f\x1e\xfa":
        preserve = instructions[0]["bytes"]
        body = instructions[1:]
        if not body:
            raise ValueError("函数只有 endbr64，放不下固定返回值")
    start, disassembled_body = _prefix_region(body, len(stub))
    if preserve:
        start = instructions[0]["address"]
    disassembled = preserve + disassembled_body
    original = lab.read_at(start, len(disassembled))
    if original != disassembled:
        raise ValueError("函数入口磁盘字节与反汇编不一致，请刷新后重试")
    new_bytes = preserve + stub + b"\x90" * (len(original) - len(preserve) - len(stub))
    return {"ops": [PatchOp(kind="return_constant", vaddr=start,
                            file_offset=lab.offset_of(start), original_bytes=original,
                            new_bytes=new_bytes,
                            note=f"{fn['name']}: 固定返回 EAX=0x{encoded:08x}")],
            "warnings": ["仅保证 32 位 EAX 返回语义；指针、浮点或结构体返回函数需人工编写汇编。"]}


def build_nop_range(lab: PatchLab, vaddr_start: int, vaddr_end: int) -> dict:
    """[start, end) 区间整段 NOP。"""
    start, end = int(vaddr_start), int(vaddr_end)
    if end <= start:
        raise ValueError("NOP 区间为空")
    if end - start > 0x10000:
        raise ValueError("NOP 区间过大（>64KB），请确认地址")
    original = lab.read_at(start, end - start)
    return {"ops": [PatchOp(kind="nop_range", vaddr=start, file_offset=lab.offset_of(start),
                            original_bytes=original, new_bytes=b"\x90" * (end - start),
                            note=f"区间 NOP 0x{start:x}-0x{end:x}")],
            "warnings": []}


def build_custom_bytes(lab: PatchLab, vaddr: int, hex_bytes: str, *,
                       expected_size: int | None = None) -> dict:
    """在指定虚拟地址写入自定义字节（等长替换，长度以原字节为准或显式给出）。"""
    cleaned = "".join(str(hex_bytes).split()).replace(",", "")
    if not cleaned or re.fullmatch(r"(?:[0-9a-fA-F]{2})+", cleaned) is None:
        raise ValueError("字节必须是非空的连续两位十六进制（如 90 或 31 d2）")
    new_bytes = bytes.fromhex(cleaned)
    address = int(vaddr)
    size = expected_size if expected_size is not None else len(new_bytes)
    if size != len(new_bytes):
        raise ValueError(f"新字节长度 {len(new_bytes)} 与目标区域 {size} 不一致")
    original = lab.read_at(address, size)
    if original == new_bytes:
        raise ValueError("新字节与原字节完全相同，无需打补丁")
    return {"ops": [PatchOp(kind="custom", vaddr=address, file_offset=lab.offset_of(address),
                            original_bytes=original, new_bytes=new_bytes,
                            note=f"自定义字节 @0x{address:x}")],
            "warnings": []}


_JCC_SHORT_NAMES = {
    0x70: "jo", 0x71: "jno", 0x72: "jb", 0x73: "jae", 0x74: "je", 0x75: "jne",
    0x76: "jbe", 0x77: "ja", 0x78: "js", 0x79: "jns", 0x7A: "jp", 0x7B: "jnp",
    0x7C: "jl", 0x7D: "jge", 0x7E: "jle", 0x7F: "jg",
}


def build_jcc_mode(lab: PatchLab, vaddr: int, mode: str = "invert") -> dict:
    """反转条件跳转（jg↔jle、jl↔jge、je↔jne…）——off-by-one 边界修复的 1 字节手法。

    短跳转（70-7F）与近跳转（0F 84-8F）的取反都是「操作码 ^ 1」，
    位移字节原样保留，文件布局不变。
    """
    if mode not in {"invert", "always", "never"}:
        raise ValueError("条件跳转模式只支持 invert / always / never")
    address = int(vaddr)
    blob = lab.read_at(address, 6)
    if blob[0] == 0x0F and 0x80 <= blob[1] <= 0x8F:
        original = bytes(blob[:6])
        if mode == "invert":
            new_bytes = bytes([0x0F, blob[1] ^ 1]) + original[2:]
        elif mode == "always":
            displacement = struct.unpack("<i", original[2:])[0]
            new_bytes = b"\xe9" + struct.pack("<i", displacement + 1) + b"\x90"
        else:
            new_bytes = b"\x90" * 6
        short_opcode = 0x70 | (blob[1] & 0x0F)
        source_name = _JCC_SHORT_NAMES.get(short_opcode, "jcc")
        note = f"条件跳转 @0x{address:x}: {source_name} → {mode}（近跳转）"
    elif 0x70 <= blob[0] <= 0x7F:
        original = bytes(blob[:2])
        if mode == "invert":
            new_bytes = bytes([blob[0] ^ 1]) + original[1:]
        elif mode == "always":
            new_bytes = b"\xeb" + original[1:]
        else:
            new_bytes = b"\x90\x90"
        note = f"条件跳转 @0x{address:x}: {_JCC_SHORT_NAMES.get(blob[0], 'jcc')} → {mode}"
    else:
        raise ValueError(
            f"0x{address:x} 处不是条件跳转（jcc）指令；仅支持短跳转（70-7F）与"
            "近跳转（0F 80-8F），请先用反汇编确认选中的指令")
    if original == new_bytes:
        raise ValueError("反转前后字节相同，无需打补丁")
    return {"ops": [PatchOp(kind="jcc_invert", vaddr=address,
                            file_offset=lab.offset_of(address),
                            original_bytes=original, new_bytes=new_bytes,
            note=note)],
            "warnings": ["控制流修改会改变校验分支；应用后应同时测试成功、失败和边界输入。"]}


def build_jcc_invert(lab: PatchLab, vaddr: int) -> dict:
    return build_jcc_mode(lab, vaddr, "invert")


def normalize_patch_arch(architecture, bits) -> str:
    """归一化 patch 用的架构标签（不支持 x86 以外时给出明确错误）。"""
    text = normalize_architecture(architecture, strict=False)
    if text not in ("amd64", "i386"):
        raise ValueError(
            f"AWDP 补丁当前支持 x86-64 / i386，目标架构为 {architecture}（{bits} 位）")
    return text


# ---------------------------------------------------------------------------
# 一键通防目录（UI 卡片与 docs/awdp_patch.md 同源的使用说明）

RECIPE_CATALOG: tuple[dict, ...] = (
    {
        "id": "seccomp",
        "name": "seccomp 沙箱注入",
        "usage": (
            "思路与社区工具 retr0-Patcher / EvilPatcher 一致：按系统调用号生成 BPF 过滤器，"
            "在 ELF 入口注入安装 shellcode（code cave + RIP 相对寻址，32 位用 call/pop 取址），"
            "先 PR_SET_NO_NEW_PRIVS 再 PR_SET_SECCOMP(MODE_FILTER)，装完过滤器后回跳原入口继续执行。"
            "文件大小与段布局不变，PIE 无关。\n"
            "适用：漏洞点一时定位不了时，先封死 execve/getshell 类攻击路径。\n"
            "用法：选一个预设规则（或按 seccomp-tools 语法写自定义规则，每行一条，如 "
            "`default kill`、`allow read`、`kill execve`），点「预览补丁」核对入口跳转与 cave 载荷，"
            "再应用。应用后务必本地跑一次服务确认自身功能没有被误伤。"),
        "fields": [
            {"key": "preset", "label": "预设规则", "kind": "select", "dynamic": True},
            {"key": "policy", "label": "自定义规则（选择“自定义”后生效）", "kind": "policy"},
        ],
        "warnings": ("白名单模式会杀掉未列出的所有系统调用，常见 glibc 程序会直接被杀；",
                     "黑名单模式挡不住 open/read/write 型读旗（ORW）攻击。"),
    },
    {
        "id": "plt_call",
        "name": "危险函数调用点劫持",
        "usage": (
            "V1ct0r 的经典手法：把反汇编里所有 `call system@plt` 的 4 字节位移（rel32）重算，"
            "指向目标函数的 PLT（如 exit / _exit / puts）。call 仍是 5 字节，文件布局不变，"
            "只改调用语义。\n"
            "适用：已知危险函数（system/execve/gets 等）且想精确替换调用点的场景。"),
        "fields": [
            {"key": "function", "label": "作用函数", "kind": "select", "dynamic": True},
            {"key": "vaddr", "label": "单处调用地址（留空处理所选函数的全部匹配调用）", "kind": "number"},
            {"key": "source", "label": "被劫持函数（PLT）", "kind": "select", "dynamic": True},
            {"key": "target", "label": "重定向目标（PLT）", "kind": "select", "dynamic": True},
        ],
        "warnings": ["目标函数与源函数参数语义不同时（如 system(char*) → exit(int)），"
                     "攻击者可控的字符串指针会被当作退出码，行为是“安全退出”，可接受。"],
    },
    {
        "id": "plt_stub",
        "name": "PLT stub 整体劫持",
        "usage": (
            "把危险函数的 PLT stub 前 5 字节改写为 `jmp 目标@plt`（E9 rel32），剩余字节 NOP，"
            "对该函数的所有调用全局生效（含程序正常业务里的调用）。\n"
            "适用：调用点太多不想逐个改，或想彻底废掉某个导入函数时。"),
        "fields": [
            {"key": "source", "label": "被劫持函数（PLT）", "kind": "select", "dynamic": True},
            {"key": "target", "label": "重定向目标（PLT）", "kind": "select", "dynamic": True},
        ],
        "warnings": ("stub 级替换影响全部调用方；若程序正常功能也依赖该函数，业务会一起被改掉。",),
    },
    {
        "id": "readlen",
        "name": "read / recv 长度收紧",
        "usage": (
            "在选中函数里定位紧邻 `read@plt` / `recv@plt` / `recvfrom@plt` 调用的 "
            "`mov edx, $imm32`（或 fgets 的 `mov esi, $imm32`），把立即数替换为安全长度。"
            "读入类漏洞的经典通防：新长度 ≤ 缓冲区实际容量（对照函数栈帧大小 sub rsp, N）。\n"
            "适用：read/recv/recvfrom/fgets 读入长度超过栈缓冲导致的溢出，网络服务同样适用。\n"
            "amd64 自动追踪 edx/esi 立即数；i386 按 cdecl 参数位置回溯 push 立即数，并保持"
            "原指令长度等长改写。"),
        "fields": [
            {"key": "function", "label": "目标函数", "kind": "select", "dynamic": True},
            {"key": "vaddr", "label": "长度立即数地址（留空处理函数内全部匹配）", "kind": "number"},
            {"key": "callee", "label": "目标调用", "kind": "select",
             "options": [{"value": "read", "label": "read（amd64 edx / i386 第3参数）"},
                         {"value": "recv", "label": "recv（amd64 edx / i386 第3参数）"},
                         {"value": "recvfrom", "label": "recvfrom（amd64 edx / i386 第3参数）"},
                         {"value": "fgets", "label": "fgets（amd64 esi / i386 第2参数）"}]},
            {"key": "size", "label": "新长度（十六进制 0x.. 或十进制）", "kind": "number",
             "default": "0x30"},
        ],
        "warnings": ("过小会截断正常输入导致业务故障；先看栈帧再定值。",),
    },
    {
        "id": "return_constant",
        "name": "函数固定返回值",
        "usage": (
            "把函数入口按完整指令边界替换为 `xor eax,eax; ret`、`or eax,-1; ret` 或"
            "`mov eax,imm32; ret`，剩余空间填 NOP。\n"
            "适用：关闭危险功能、让鉴权或索引检查稳定失败、替代返回值不确定的单字节 ret。"),
        "fields": [
            {"key": "function", "label": "目标函数", "kind": "select", "dynamic": True},
            {"key": "value", "label": "EAX 返回值（支持 -1 / 十六进制）", "kind": "number", "default": "0"},
        ],
        "warnings": ("仅适用于整数/布尔返回语义；指针、浮点和结构体返回需手动汇编。",),
    },
    {
        "id": "jcc_mode",
        "name": "条件分支控制",
        "usage": (
            "精确修改一条短/近条件跳转：取反、强制跳转，或永不跳转。保持原目标地址和区域长度。\n"
            "适用：负数绕过、off-by-one、权限判断和错误分支修补；先从反汇编页复制指令地址。"),
        "fields": [
            {"key": "vaddr", "label": "条件跳转指令地址", "kind": "number"},
            {"key": "mode", "label": "处理方式", "kind": "select", "options": [
                {"value": "invert", "label": "取反条件"},
                {"value": "always", "label": "强制跳转"},
                {"value": "never", "label": "永不跳转"},
            ]},
        ],
        "warnings": ("必须测试条件成立、不成立和边界值三条路径。",),
    },
    {
        "id": "nop_function",
        "name": "整函数 NOP",
        "usage": (
            "按反汇编指令边界把选中函数体全部填 0x90。它会连 ret/尾跳转一起移除，执行可能"
            "继续落入相邻代码。\n"
            "仅适合明确不可达的代码区；关闭可调用函数时优先使用固定返回值或 ret 化。"),
        "fields": [{"key": "function", "label": "目标函数", "kind": "select", "dynamic": True}],
        "warnings": ("可调用函数整段 NOP 可能发生控制流贯穿；不要把它当作安全返回。",),
    },
    {
        "id": "ret_function",
        "name": "函数 ret 化",
        "usage": (
            "只把函数首字节改成 0xC3（ret）——AWDP「最小修改」版本：一处 1 字节改动，"
            "函数被调用即刻返回。\n"
            "适用：同 nop_function，但改动更小、更容易过尺寸/哈希校验。"),
        "fields": [{"key": "function", "label": "目标函数", "kind": "select", "dynamic": True}],
        "warnings": ("返回值 eax 为调用前残留值，不可控；调用方依赖返回值时需一并检查。",),
    },
)
