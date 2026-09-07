"""seccomp 沙箱通防：入口 trampoline + code cave 注入，不改文件大小。

思路与社区工具 retr0-Patcher / EvilPatcher 一致：
1. 用 syscall 号生成经典 BPF 过滤器（arch 校验 + nr 白/黑名单）；
2. 在可执行 PT_LOAD 的全零 cave 里放安装 shellcode + 被覆盖的入口前缀 +
   回跳 jmp + 过滤器数据；
3. 入口前 ≥5 字节（按指令边界）替换为 `jmp rel32` 进 cave。
shellcode 全程 RIP 相对（i386 用 call/pop 取址），PIE 无关。
"""
from __future__ import annotations

import struct

from pwncraft.core.syscalls import lookup_syscall, syscall_table
from .patch_core import PatchLab, PatchOp, entry_prefix_bytes, find_code_cave, rel32_jmp

# --- 常量（内核 uapi 语义） ------------------------------------------------
_PRCTL = {"amd64": 157, "i386": 172}
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_RET_ALLOW = 0x7FFF0000
_RET_KILL_PROCESS = 0x80000000
_AUDIT_ARCH = {"amd64": 0xC000003E, "i386": 0x40000003}

_BPF_LD_W_ABS = 0x20
_BPF_JEQ_K = 0x15
_BPF_RET_K = 0x06

SUPPORTED_ARCHS = ("amd64", "i386")

SECCOMP_PRESETS: dict[str, dict] = {
    "blacklist_min": {
        "name": "黑名单 · 仅禁 execve 系",
        "default": "allow",
        "kill": ("execve", "execveat"),
        "allow": (),
        "description": "只封杀 execve/execveat，其他系统调用一律放行。"
                       "阻断 getshell 与 one_gadget 直接拿 shell 的路径。",
        "warnings": ("不能阻止 open/read/write 型读旗攻击（ORW）；",
                     "若漏洞本身允许任意读文件，仍需收紧 read/open 规则或修复漏洞点。"),
    },
    "blacklist_fork": {
        "name": "黑名单 · 禁 execve + 进程创建",
        "default": "allow",
        "kill": ("execve", "execveat", "fork", "vfork", "clone"),
        "allow": (),
        "description": "在 blacklist_min 基础上同时封杀 fork/vfork/clone，"
                       "用于阻断反弹 shell / 多进程逃逸。",
        "warnings": ("服务自身若 fork（如经典 fork 型 echo 服务）会被一同封死，"
                     "务必先确认程序不依赖这些调用；",
                     "不能阻止 ORW 型读旗攻击。"),
    },
    "orw_whitelist": {
        "name": "白名单 · 仅 read/write/exit",
        "default": "kill",
        "kill": (),
        "allow": ("read", "write", "exit", "exit_group"),
        "description": "最严格模式：只允许 read/write/exit(exit_group)，"
                       "其余系统调用一律 SIGKILL。",
        "warnings": ("malloc/printf 等库函数依赖 brk/mmap/fstat 等调用，"
                     "常见 glibc 程序会直接被杀，仅适用于极简静态逻辑；",
                     "open 被禁意味着自己也无法正常打开文件；"
                     "一般比赛不建议直接使用，除非确认目标行为极简。"),
    },
}


def _bpf(code: int, jt: int, jf: int, k: int) -> bytes:
    """struct sock_filter 布局：code(u16) jt(u8) jf(u8) k(u32)，共 8 字节。

    实测踩坑：打成 "<BBHI" 会让 jt 溢入 code 高字节（0x0215 非法操作码），
    内核对 PR_SET_SECCOMP 直接返回 EINVAL。
    """
    return struct.pack("<HBBI", code & 0xFFFF, jt & 0xFF, jf & 0xFF, k & 0xFFFFFFFF)


def build_bpf_filter(arch: str, kill: tuple[int, ...] = (), allow: tuple[int, ...] = ()) -> bytes:
    """经典 seccomp 过滤器：arch 不匹配 → KILL；nr 命中 → 动作；否则默认动作。

    blacklist 模式（kill 非空）：命中即 KILL_PROCESS，默认 ALLOW。
    whitelist 模式（allow 非空）：命中即 ALLOW，默认 KILL_PROCESS。
    """
    if arch not in _AUDIT_ARCH:
        raise ValueError(f"seccomp 注入仅支持 {SUPPORTED_ARCHS}，当前: {arch}")
    blacklist = bool(kill)
    entries = tuple(kill) if blacklist else tuple(allow)
    if not entries:
        raise ValueError("过滤规则为空：需要至少一个 kill 或 allow 系统调用")
    if len(entries) > 200:
        raise ValueError("过滤规则过多（>200），超出常见 cave 容量")
    numbers = tuple(int(n) & 0xFFFFFFFF for n in entries)
    action = _RET_KILL_PROCESS if blacklist else _RET_ALLOW
    default = _RET_ALLOW if blacklist else _RET_KILL_PROCESS
    count = len(numbers)
    kill_line = (4 + count) if blacklist else (3 + count)

    insns = [_bpf(_BPF_LD_W_ABS, 0, 0, 4),                    # A = arch
             _bpf(_BPF_JEQ_K, 0, kill_line - 2, _AUDIT_ARCH[arch]),  # arch 不符 → KILL
             _bpf(_BPF_LD_W_ABS, 0, 0, 0)]                    # A = nr
    for index, number in enumerate(numbers):
        insns.append(_bpf(_BPF_JEQ_K, count - index, 0, number))
    insns.append(_bpf(_BPF_RET_K, 0, 0, default))
    insns.append(_bpf(_BPF_RET_K, 0, 0, action))
    return b"".join(insns)


def shellcode_length(arch: str) -> int:
    return 71 if arch == "amd64" else 67


def build_install_shellcode(arch: str, shellcode_vaddr: int,
                            filter_vaddr: int, filter_len: int) -> bytes:
    """安装过滤器的位置无关 shellcode；返回字节数恰为 shellcode_length(arch)。

    amd64 必须保存/恢复 rdx：入口 ABI 约定 rdx=rtld_fini，_start 在
    trampoline 回跳后执行 `mov r9, rdx`，污染它会退栈时跳进 fprog 栈地址。
    """
    if arch == "amd64":
        code = bytearray()
        code += b"\x52"                                    # push rdx（保存 rtld_fini）
        code += b"\xb8\x9d\x00\x00\x00"                    # mov eax, 157 (prctl)
        code += b"\xbf\x26\x00\x00\x00"                    # mov edi, 38  (PR_SET_NO_NEW_PRIVS)
        code += b"\xbe\x01\x00\x00\x00"                    # mov esi, 1
        code += b"\x31\xd2"                                # xor edx, edx
        code += b"\x45\x31\xd2"                            # xor r10d, r10d
        code += b"\x45\x31\xc0"                            # xor r8d, r8d
        code += b"\x0f\x05"                                # syscall
        lea_at = len(code)
        code += b"\x4c\x8d\x0d\x00\x00\x00\x00"            # lea r9, [rip+disp] → filter
        code += b"\x41\x51"                                # push r9           (fprog.filter)
        code += b"\x68" + struct.pack("<I", filter_len)    # push imm32        (fprog.len)
        code += b"\x48\x89\xe2"                            # mov rdx, rsp      (&fprog)
        code += b"\xb8\x9d\x00\x00\x00"                    # mov eax, 157
        code += b"\xbf\x16\x00\x00\x00"                    # mov edi, 22  (PR_SET_SECCOMP)
        code += b"\xbe\x02\x00\x00\x00"                    # mov esi, 2   (MODE_FILTER)
        code += b"\x45\x31\xd2"                            # xor r10d, r10d
        code += b"\x45\x31\xc0"                            # xor r8d, r8d
        code += b"\x0f\x05"                                # syscall
        code += b"\x48\x83\xc4\x10"                        # add rsp, 16
        code += b"\x5a"                                    # pop rdx（恢复 rtld_fini）
        disp = filter_vaddr - (shellcode_vaddr + lea_at + 7)
        code[lea_at + 3:lea_at + 7] = struct.pack("<i", disp)
        assert len(code) == shellcode_length("amd64")
        return bytes(code)

    # i386：无 RIP 相对寻址，用 call/pop 取当前地址
    code = bytearray()
    code += b"\xb8\xac\x00\x00\x00"                        # mov eax, 172 (prctl)
    code += b"\xbb\x26\x00\x00\x00"                        # mov ebx, 38
    code += b"\xb9\x01\x00\x00\x00"                        # mov ecx, 1
    code += b"\x31\xd2"                                    # xor edx, edx
    code += b"\x31\xf6"                                    # xor esi, esi
    code += b"\x31\xff"                                    # xor edi, edi
    code += b"\xcd\x80"                                    # int 0x80
    code += b"\xe8\x00\x00\x00\x00"                        # call next
    pop_at = len(code)
    code += b"\x5b"                                        # pop ebx → 此处运行时地址
    add_at = len(code)
    code += b"\x81\xc3\x00\x00\x00\x00"                    # add ebx, disp → filter 地址
    code += b"\x53"                                        # push ebx          (fprog.filter)
    code += b"\x68" + struct.pack("<I", filter_len)        # push imm32        (fprog.len)
    code += b"\x89\xe2"                                    # mov edx, esp      (&fprog)
    code += b"\xb8\xac\x00\x00\x00"                        # mov eax, 172
    code += b"\xbb\x16\x00\x00\x00"                        # mov ebx, 22
    code += b"\xb9\x02\x00\x00\x00"                        # mov ecx, 2
    code += b"\x31\xf6"                                    # xor esi, esi
    code += b"\x31\xff"                                    # xor edi, edi
    code += b"\xcd\x80"                                    # int 0x80
    code += b"\x83\xc4\x08"                                # add esp, 8
    disp = filter_vaddr - (shellcode_vaddr + pop_at)
    code[add_at + 2:add_at + 6] = struct.pack("<i", disp)
    assert len(code) == shellcode_length("i386")
    return bytes(code)


def resolve_policy_names(names, arch: str) -> tuple[int, ...]:
    resolved: list[int] = []
    for name in names:
        spec = lookup_syscall(str(name).strip().lower(), arch)
        if spec is None:
            supported = ", ".join(sorted(syscall_table(arch)))
            raise ValueError(
                f"系统调用 {name!r} 不在 {arch} 已知调用表内；支持: {supported}")
        resolved.append(spec.number)
    return tuple(dict.fromkeys(resolved))


def build_seccomp_ops(lab: PatchLab, *, arch: str, kill: tuple[str, ...] = (),
                      allow: tuple[str, ...] = (), entry_lines: list[dict]) -> dict:
    """构建 seccomp 注入的两个 PatchOp（入口 trampoline + cave 载荷）。"""
    if arch not in SUPPORTED_ARCHS:
        raise ValueError(f"seccomp 注入仅支持 {SUPPORTED_ARCHS}，当前: {arch}")
    geometry = lab.geometry()
    if (64 if geometry["is64"] else 32) != (64 if arch == "amd64" else 32):
        raise ValueError(f"目标文件位数与 {arch} 不符，请确认导入的 ELF 架构")
    kill_nums = resolve_policy_names(kill, arch)
    allow_nums = resolve_policy_names(allow, arch)
    bpf = build_bpf_filter(arch, kill_nums, allow_nums)

    entry = int(geometry["entry"])
    entry_first = lab.read_at(entry, 1)
    if entry_first == b"\xe9":
        raise ValueError(
            "入口首字节已是 jmp rel32——目标可能已注入过 trampoline（如重复打 seccomp 补丁）。"
            "请先在「补丁管理」撤销旧补丁，或换用未修改的原始副本重放")
    prefix = entry_prefix_bytes(entry_lines)
    prefix_len = len(prefix)
    needed = shellcode_length(arch) + prefix_len + 5 + len(bpf)
    cave = find_code_cave(lab.binary, needed, geometry=geometry)

    shellcode_vaddr = cave["vaddr"]
    filter_vaddr = shellcode_vaddr + shellcode_length(arch) + prefix_len + 5
    shellcode = build_install_shellcode(arch, shellcode_vaddr, filter_vaddr, len(bpf) // 8)
    jump_back_at = shellcode_vaddr + len(shellcode) + prefix_len
    cave_payload = (shellcode + prefix + rel32_jmp(jump_back_at, entry + prefix_len) + bpf)

    cave_original = lab.read(cave["offset"], len(cave_payload))
    if cave_original.strip(b"\x00"):
        raise ValueError("code cave 不再是全零，文件已被外部修改")
    entry_original = lab.read_at(entry, prefix_len)

    preset_note = "禁 " + "/".join(kill) if kill else "仅允许 " + "/".join(allow)
    ops = [
        PatchOp(kind="seccomp_entry", vaddr=entry, file_offset=lab.offset_of(entry),
                original_bytes=entry_original,
                new_bytes=rel32_jmp(entry, shellcode_vaddr) + b"\x90" * (prefix_len - 5),
                note=f"seccomp 沙箱入口跳转（覆盖 {prefix_len} 字节前缀，已存入 cave）"),
        PatchOp(kind="seccomp_cave", vaddr=shellcode_vaddr, file_offset=cave["offset"],
                original_bytes=cave_original, new_bytes=cave_payload,
                note=f"seccomp 安装载荷 + BPF 过滤器（{preset_note}）"),
    ]
    warnings = [
        "入口前缀指令被搬入 cave 执行；若其中含 RIP 相对寻址需人工复核（_start 开头通常没有）。",
        "应用后请实际运行一次服务确认未误伤自身功能，再提交比赛。",
    ]
    return {"ops": ops, "warnings": warnings, "cave": cave,
            "entry": entry, "prefix_len": prefix_len,
            "filter_insns": len(bpf) // 8}
