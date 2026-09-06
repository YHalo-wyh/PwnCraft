from pwn import *
context.log_level = 'debug'
io = remote('pwn.challenge.ctf.show',28159)
io.interactive()
