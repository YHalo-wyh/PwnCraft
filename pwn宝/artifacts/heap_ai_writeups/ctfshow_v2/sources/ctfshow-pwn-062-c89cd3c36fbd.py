from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
if args['REMOTE']:
    io = remote('pwn.challenge.ctf.show', 28189)
else:
    io = process('./pwn')
# 24 bytes
# https://www.exploit-db.com/shellcodes/43550
