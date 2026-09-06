from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
if args['REMOTE']:
    io = remote('pwn.challenge.ctf.show', 28114)
else:
    io = process('./pwn')
# 23 bytes
# https://www.exploit-db.com/exploits/36858/
