from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')
io = remote('pwn.challenge.ctf.show', 28145)
elf = ELF('./pwn')
libc = ELF('/home/ctfshow/libc/32bit/libc-2.27.so')
ctfshow = elf.sym['ctfshow']
