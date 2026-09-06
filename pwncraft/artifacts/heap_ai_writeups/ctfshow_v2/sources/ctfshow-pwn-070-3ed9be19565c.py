from pwn import *
context(log_level='debug',os='linux',arch='amd64')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28175)
