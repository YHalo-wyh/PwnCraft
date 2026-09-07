"""字节码查询：常用指令 ↔ 机器码静态目录、参数化编码器、原始字节反汇编。

目录覆盖 AWDP patch 高频指令（NOP 族 / 控制流 / 立即数传送 / 自清零），
来源为 Intel 手册常用编码与社区机器码对照表（Hello CTF AWD 技巧）。
不引入 keystone 等汇编器依赖；任意汇编→字节用「模板编码 + objdump 反查」覆盖。
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

# (助记符, 机器码, 说明, 标签)
CATALOG: tuple[tuple[str, str, str, str], ...] = (
    ("nop", "90", "单字节 NOP；填充指令最常用", "nop 填充"),
    ("nop 2", "66 90", "2 字节 NOP", "nop 填充"),
    ("nop 3", "0f 1f 00", "3 字节 NOP", "nop 填充"),
    ("nop 4", "0f 1f 40 00", "4 字节 NOP", "nop 填充"),
    ("nop 5", "0f 1f 44 00 00", "5 字节 NOP；正好覆盖一条 call rel32", "nop 填充"),
    ("nop 6", "66 0f 1f 44 00 00", "6 字节 NOP", "nop 填充"),
    ("nop 7", "0f 1f 80 00 00 00 00", "7 字节 NOP", "nop 填充"),
    ("nop 8", "0f 1f 84 00 00 00 00 00", "8 字节 NOP", "nop 填充"),
    ("nop 9", "66 0f 1f 84 00 00 00 00 00", "9 字节 NOP", "nop 填充"),
    ("nop 10", "66 2e 0f 1f 84 00 00 00 00 00", "10 字节 NOP", "nop 填充"),
    ("ret", "c3", "近返回；函数 ret 化 / 截断执行流", "控制流"),
    ("ret imm16", "c2 iw", "返回并弹出 imm16 字节栈", "控制流"),
    ("leave", "c9", "mov rsp,rbp; pop rbp；配合 ret 还原栈帧", "控制流"),
    ("leave; ret", "c9 c3", "栈题常用：直接回到上一层返回地址", "控制流"),
    ("syscall", "0f 05", "amd64 系统调用（rax=调用号）", "控制流"),
    ("int 0x80", "cd 80", "i386 系统调用（eax=调用号）", "控制流"),
    ("int3", "cc", "断点陷阱；反调试/制造崩溃", "控制流"),
    ("hlt", "f4", "停机（特权指令，用户态触发 SIGSEGV）", "控制流"),
    ("ud2", "0f 0b", "非法指令，触发 SIGILL", "控制流"),
    ("endbr64", "f3 0f 1e fa", "CET/IBT 入口标记（新 GCC 函数头常见）", "入口"),
    ("endbr32", "f3 0f 1e fb", "32 位 CET/IBT 入口标记", "入口"),
    ("jmp rel8", "eb cb", "短跳转；位移=目标-(当前+2)，范围 ±127", "跳转"),
    ("jmp rel32", "e9 cd", "近跳转；位移=目标-(当前+5)", "跳转"),
    ("call rel32", "e8 cd", "近调用；位移=目标-(当前+5)", "跳转"),
    ("je rel8", "74 cb", "等于跳转（ZF=1）", "跳转"),
    ("jne rel8", "75 cb", "不等于跳转", "跳转"),
    ("jg rel8", "7f cb", "有符号大于；off-by-one 常改 jg↔jge", "跳转"),
    ("jge rel8", "7d cb", "有符号大于等于", "跳转"),
    ("jl rel8", "7c cb", "有符号小于", "跳转"),
    ("jle rel8", "7e cb", "有符号小于等于", "跳转"),
    ("ja rel8", "77 cb", "无符号大于", "跳转"),
    ("jbe rel8", "76 cb", "无符号小于等于", "跳转"),
    ("je rel32", "0f 84 cd", "长条件跳转（不挤 rel8 时用）", "跳转"),
    ("jne rel32", "0f 85 cd", "长条件跳转", "跳转"),
    ("jg rel32", "0f 8f cd", "长条件跳转", "跳转"),
    ("jmp rax", "ff e0", "寄存器跳转；hook/跳 shellcode 常用", "跳转"),
    ("call rax", "ff d0", "寄存器调用", "跳转"),
    ("push rbp", "55", "函数序言第一步", "栈"),
    ("pop rbp", "5d", "", "栈"),
    ("pop rdi", "5f", "amd64 恢复第一个参数", "栈"),
    ("pop rsi", "5e", "amd64 恢复第二个参数", "栈"),
    ("pop rdx", "5a", "amd64 恢复第三个参数", "栈"),
    ("push imm8", "6a ib", "压入单字节立即数（i386 传参常见）", "栈"),
    ("push imm32", "68 id", "压入 4 字节立即数", "栈"),
    ("xor eax,eax", "31 c0", "eax 清零；比 mov eax,0 短", "清零"),
    ("xor edx,edx", "31 d2", "edx 清零（read 第三参数 0）", "清零"),
    ("xor esi,esi", "31 f6", "esi 清零", "清零"),
    ("xor edi,edi", "31 ff", "edi 清零（fd=0 即 stdin）", "清零"),
    ("mov eax,imm32", "b8 id", "eax = 立即数（如系统调用号）", "传送"),
    ("mov edi,imm32", "bf id", "edi = 立即数（第一参数）", "传送"),
    ("mov esi,imm32", "be id", "esi = 立即数（第二参数；fgets 长度）", "传送"),
    ("mov edx,imm32", "ba id", "edx = 立即数（第三参数；read 长度）", "传送"),
    ("mov ecx,imm32", "b9 id", "ecx = 立即数", "传送"),
    ("mov rdi,imm32", "48 c7 c7 id", "rdi = 符号扩展 imm32（64 位第一参数）", "传送"),
    ("mov rdi,rax", "48 89 c7", "寄存器间传送", "传送"),
    ("add rsp,imm8", "48 83 c4 ib", "栈平衡（配合跳转缝合时用）", "栈"),
)

_REGISTER_OPCODE = {
    "eax": 0xB8, "ecx": 0xB9, "edx": 0xBA, "ebx": 0xBB,
    "esp": 0xBC, "ebp": 0xBD, "esi": 0xBE, "edi": 0xBF,
}
_XOR_SELF = {"eax": b"\x31\xc0", "ecx": b"\x31\xc9", "edx": b"\x31\xd2",
             "ebx": b"\x31\xdb", "esi": b"\x31\xf6", "edi": b"\x31\xff",
             "esp": b"\x31\xe4", "ebp": b"\x31\xed"}
_CANONICAL_NOPS = ("90", "66 90", "0f 1f 00", "0f 1f 40 00", "0f 1f 44 00 00",
                   "66 0f 1f 44 00 00", "0f 1f 80 00 00 00 00",
                   "0f 1f 84 00 00 00 00 00", "66 0f 1f 84 00 00 00 00 00",
                   "66 2e 0f 1f 84 00 00 00 00 00")


def catalog_entries(query: str = "") -> list[dict]:
    """按助记符 / 字节 / 标签模糊过滤目录。"""
    needle = str(query).strip().lower().replace(" ", "")
    result = []
    for mnemonic, blob, note, tag in CATALOG:
        flat = mnemonic.lower().replace(" ", "") + "|" + blob.replace(" ", "") + "|" + tag.lower()
        if not needle or needle in flat:
            result.append({"mnemonic": mnemonic, "bytes": blob, "note": note, "tag": tag})
    return result


def encode_template(kind: str, params: dict) -> dict:
    """参数化编码：nop 长度 / mov r32,imm32 / push imm / rel32 跳转位移计算。"""
    kind = str(kind).strip().lower()
    if kind == "nop":
        length = int(params.get("length") or 1)
        if not 1 <= length <= len(_CANONICAL_NOPS):
            raise ValueError(f"规范 NOP 序列长度为 1-{len(_CANONICAL_NOPS)}")
        blob = _CANONICAL_NOPS[length - 1]
        return {"bytes": blob, "note": f"{length} 字节规范 NOP"}
    if kind == "mov_reg_imm32":
        register = str(params.get("register") or "").lower()
        if register not in _REGISTER_OPCODE:
            raise ValueError(f"寄存器须为 {sorted(_REGISTER_OPCODE)} 之一")
        value = int(str(params.get("value") or "0"), 0)
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("立即数超出 u32 范围")
        blob = f"{_REGISTER_OPCODE[register]:02x} " + struct.pack("<I", value).hex(" ")
        return {"bytes": blob, "note": f"mov {register}, 0x{value:x}"}
    if kind == "xor_reg":
        register = str(params.get("register") or "").lower()
        if register not in _XOR_SELF:
            raise ValueError(f"寄存器须为 {sorted(_XOR_SELF)} 之一")
        return {"bytes": _XOR_SELF[register].hex(" "), "note": f"xor {register},{register}"}
    if kind in ("jmp_rel32", "call_rel32"):
        origin = int(str(params.get("origin") or "0"), 0)
        target = int(str(params.get("target") or "0"), 0)
        delta = target - (origin + 5)
        if not -0x80000000 <= delta < 0x80000000:
            raise ValueError(f"位移越界: {delta:#x}（两地址距离超过 ±2GB）")
        opcode = "e9" if kind == "jmp_rel32" else "e8"
        return {"bytes": f"{opcode} " + struct.pack("<i", delta).hex(" "),
                "note": f"0x{origin:x} → 0x{target:x}（rel32 = {delta:#x}）"}
    raise ValueError(f"未知编码模板: {kind}（支持 nop / mov_reg_imm32 / xor_reg / jmp_rel32 / call_rel32）")


_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def disasm_raw(hex_bytes: str, *, bits: int, runner, work_dir: Path) -> dict:
    """用已放行的 objdump 把原始字节反汇编（-b binary，Intel 语法）。"""
    cleaned = "".join(str(hex_bytes).split()).replace(",", "")
    if not cleaned or not _HEX_RE.match(cleaned) or len(cleaned) > 4096:
        raise ValueError("请输入 1-2048 字节的连续十六进制（如 48 89 e5 或 4889e5）")
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    raw_path = work_dir / "patch_disasm.bin"
    raw_path.write_bytes(bytes.fromhex(cleaned))
    machine = "i386:x86-64" if int(bits) == 64 else "i386"
    result = runner.run_tool("objdump", [
        "-D", "-b", "binary", "-m", machine, "-M", "intel", "--",
        runner.to_wsl_path(raw_path)])
    if not result.ok:
        raise RuntimeError(f"objdump 反汇编失败: {result.combined_output()}")
    instructions = []
    for line in result.stdout.splitlines():
        text = line.strip()
        if not re.match(r"^[0-9a-fA-F]+:", text):
            continue
        address, _, rest = text.partition(":")
        instructions.append({"offset": int(address, 16), "text": rest.strip()})
    return {"bytes": cleaned, "machine": machine, "instructions": instructions}
