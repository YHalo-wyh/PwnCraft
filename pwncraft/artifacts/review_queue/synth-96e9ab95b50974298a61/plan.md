# 合成计划 · srop

- 策略：SROP（sigreturn 帧）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\greatwall\HashArchive\x\pwn`  sha256=`615ccfa2d5a6c99117d0265646f6f30c01888651633ca9e3a4401a7920d239fc`
- 保护：PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL
- 往返自检：ROUND_TRIP_ISSUES（ERROR 1 条）
- 运行时验证：NOT_RUN（未执行）

## 步骤
1. 构造 SigreturnFrame(execve) 
2. syscall; ret 触发 rt_sigreturn
3. 帧内寄存器完成 execve('/bin/sh')

## 缺口
- 控制流劫持偏移未证明（需要崩溃/调试证据）
- rax 控制 gadget 未证明（sigreturn 需要）

## 证据
- syscall @ 0x402180

## 未解析常量
- OFFSET（到保存返回地址的填充长度）
- POP_RAX（sigreturn 号需要）
- BINSH（壳字符串地址）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
