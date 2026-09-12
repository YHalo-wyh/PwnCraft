# 合成计划 · ret2win

- 策略：ret2win（跳过程序内现成调用点）（status=ready）
- 目标：`F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_ret2win`  sha256=`242167adf3d91baeaf01dc6c6bb0a156fa743842c6a5dbb48127c33908f606cf`
- 保护：PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL
- 往返自检：ROUND_TRIP_CLEAN（ERROR 0 条）
- 运行时验证：VERIFIED_SHELL（生成的 EXP 打通目标（marker 命中））

## 步骤
1. 填充到保存返回地址的偏移
2. 先落一次 ret（x86-64 16 字节栈对齐）
3. 覆盖返回地址为程序内调用点
4. 该调用点自带命令参数，无需额外 ROP

## 证据
- 0x4011c1: call execve
- 参数地址 0x402028
- gdb: Program received signal SIGSEGV
- gdb: rip=0x40123a
- gdb: rbp=0x6161617261616171
- gdb: rsp=0x7fffffffdde8
- cyclic: offset = 0x48（方法 saved_rbp）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
