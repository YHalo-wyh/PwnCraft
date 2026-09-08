"""一键通防手法：PLT 劫持、read/fgets 长度收紧、函数 NOP / ret 化、自定义字节。

全部手法输出 PatchOp 列表（先预览后应用），只做等长替换，不改文件大小。
函数与 PLT 信息来自 code_analysis 的 objdump 真值，本模块不做无依据猜测。
"""
from __future__ import annotations

import re
import struct

from pwncraft.core.syscalls import normalize_architecture
from .patch_core import PatchLab, PatchOp, parse_instruction_lines

_CALL_PLT_RE = re.compile(r"^\s*call[qw]?\s+([0-9a-fA-F]+)\s+<([^>]+)>")
_MOV_IMM32_RE = re.compile(r"^\s*mov[q]?\s+\$0x([0-9a-fA-F]+),%(e?(?:dx|si|di|cx|ax))\b")

# amd64 第三参数（read 计数）与 fgets 第二参数（尺寸）的 imm32 载体寄存器
_LENGTH_REGISTERS = {
    "read": ("edx",),
    "fgets": ("esi",),
}
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
                            target: str) -> dict:
    """把所有 `call source@plt` 的 rel32 重定向到 target@plt（V1ct0r 手法）。"""
    stubs = extract_plt_stubs(functions)
    if source not in stubs:
        raise ValueError(f"PLT 里没有 {source}@plt（可用: {', '.join(sorted(stubs)) or '无'}）")
    if target not in stubs:
        raise ValueError(f"PLT 里没有 {target}@plt（可用: {', '.join(sorted(stubs)) or '无'}）")
    sites = find_call_sites(functions, source)
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


def build_read_length(lab: PatchLab, functions: list[dict], function: str,
                      callee: str, new_size: int) -> dict:
    """收紧选中函数里传给 read/fgets 的长度立即数（仅 amd64 寄存器传参）。"""
    if callee not in _LENGTH_REGISTERS:
        raise ValueError("长度收紧目前支持 read（edx）与 fgets（esi）")
    bits = 64 if lab.geometry()["is64"] else 32
    if bits != 64:
        raise ValueError(
            "32 位下 read/fgets 走栈传参（push $imm），无稳定的立即数模式；"
            "请改用「手动 Patch」在字节码查询辅助下改写 push 立即数")
    size = int(new_size)
    if not 0 < size <= 0xFFFFFFFF:
        raise ValueError("新长度超出 u32 范围")
    fn, instructions = _function_instructions(functions, function)
    registers = _LENGTH_REGISTERS[callee]
    ops: list[PatchOp] = []
    for index, insn in enumerate(instructions):
        match = _MOV_IMM32_RE.match(insn["text"] or "")
        if not match or match[2] not in registers or insn["size"] != 5:
            continue
        # 立即数必须流向随后的 callee@plt 调用（允许中间隔着最多 4 条指令）
        window = instructions[index + 1:index + 6]
        if not any(_calls_callee(w["text"], callee) for w in window):
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
    if not ops:
        raise ValueError(
            f"{function!r} 内未找到紧邻 {callee}@plt 的 mov $imm32,%{registers[0]} 模式；"
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
    return {"ops": ops, "warnings": ["NOP 化后函数仍会被调用并原样返回（副作用消失），确认无返回值依赖。"]}


def build_ret_function(lab: PatchLab, functions: list[dict], function: str) -> dict:
    """函数首字节改为 0xC3（最小修改的“废函数”手法）。"""
    fn, instructions = _function_instructions(functions, function)
    start = instructions[0]["address"]
    original = lab.read_at(start, 1)
    ops = [PatchOp(kind="ret_function", vaddr=start, file_offset=lab.offset_of(start),
                   original_bytes=original, new_bytes=b"\xc3",
                   note=f"{fn['name']}: 首字节 → ret（返回值 eax 为调用前残留值）")]
    return {"ops": ops, "warnings": ["直接 ret 的返回值不可控；调用方若依赖返回值判断，需一并检查。"]}


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


def build_jcc_invert(lab: PatchLab, vaddr: int) -> dict:
    """反转条件跳转（jg↔jle、jl↔jge、je↔jne…）——off-by-one 边界修复的 1 字节手法。

    短跳转（70-7F）与近跳转（0F 84-8F）的取反都是「操作码 ^ 1」，
    位移字节原样保留，文件布局不变。
    """
    address = int(vaddr)
    blob = lab.read_at(address, 6)
    if blob[0] == 0x0F and 0x84 <= blob[1] <= 0x8F:
        original = bytes(blob[:6])
        new_bytes = bytes([0x0F, blob[1] ^ 1]) + original[2:]
        short_opcode = 0x70 | (blob[1] & 0x0F)
        note = (f"反转条件跳转 @0x{address:x}"
                f"（{_JCC_SHORT_NAMES.get(short_opcode, 'jcc')} → "
                f"{_JCC_SHORT_NAMES.get(short_opcode ^ 1, 'jcc')}，近跳转）")
    elif 0x70 <= blob[0] <= 0x7F:
        original = bytes(blob[:2])
        new_bytes = bytes([blob[0] ^ 1]) + original[1:]
        note = (f"反转条件跳转 @0x{address:x}"
                f"（{_JCC_SHORT_NAMES.get(blob[0], 'jcc')} → "
                f"{_JCC_SHORT_NAMES.get(blob[0] ^ 1, 'jcc')}）")
    else:
        raise ValueError(
            f"0x{address:x} 处不是条件跳转（jcc）指令；仅支持短跳转（70-7F）与"
            "近跳转（0F 84-8F），请先用反汇编确认选中的指令")
    if original == new_bytes:
        raise ValueError("反转前后字节相同，无需打补丁")
    return {"ops": [PatchOp(kind="jcc_invert", vaddr=address,
                            file_offset=lab.offset_of(address),
                            original_bytes=original, new_bytes=new_bytes,
                            note=note)],
            "warnings": ["条件反转只改变跳转方向，边界语义（多 1/少 1）需结合题意确认。"]}


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
        "name": "read / fgets 长度收紧",
        "usage": (
            "在选中函数里定位紧邻 `read@plt` 调用的 `mov edx, $imm32`（或 fgets 的 "
            "`mov esi, $imm32`），把立即数替换为安全长度。栈溢出的经典通防：新长度 ≤ "
            "缓冲区实际容量（对照函数栈帧大小 sub rsp, N）。\n"
            "适用：read/fgets 读入长度超过栈缓冲导致的溢出。\n"
            "限制：仅支持 64 位（寄存器传参）；32 位走栈传参（push $imm），请用「手动 Patch」"
            "配合字节码查询改写。"),
        "fields": [
            {"key": "function", "label": "目标函数", "kind": "select", "dynamic": True},
            {"key": "callee", "label": "目标调用", "kind": "select",
             "options": [{"value": "read", "label": "read（edx）"},
                         {"value": "fgets", "label": "fgets（esi）"}]},
            {"key": "size", "label": "新长度（十六进制 0x.. 或十进制）", "kind": "number",
             "default": "0x30"},
        ],
        "warnings": ("过小会截断正常输入导致业务故障；先看栈帧再定值。",),
    },
    {
        "id": "nop_function",
        "name": "整函数 NOP",
        "usage": (
            "按反汇编指令边界把选中函数体全部填 0x90（标准单字节 NOP）。调用方照常进入并"
            "“空转”返回。\n"
            "适用：废掉后门函数 / 明显的危险逻辑。"),
        "fields": [{"key": "function", "label": "目标函数", "kind": "select", "dynamic": True}],
        "warnings": ("副作用（全局状态修改、返回值）一并消失，确认无返回值/副作用依赖。",),
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
