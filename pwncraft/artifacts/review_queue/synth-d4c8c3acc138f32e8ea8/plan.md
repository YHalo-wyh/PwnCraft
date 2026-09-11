# 合成计划 · srop

- 策略：SROP（sigreturn 帧）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_srop`  sha256=`9776695d26e65be2da0d5852703096c3d3ff63fd38d7bbc7515b4457dc0f0241`
- 保护：PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL
- 往返自检：ROUND_TRIP_CLEAN（ERROR 0 条）
- 运行时验证：NOT_RUN（未执行）

## 步骤
1. 构造 SigreturnFrame(execve) 
2. syscall; ret 触发 rt_sigreturn
3. 帧内寄存器完成 execve('/bin/sh')

## 缺口
- 控制流劫持偏移未证明（需要崩溃/调试证据）
- rax 控制 gadget 未证明（sigreturn 需要）

## 证据
- syscall @ 0x401195

## 未解析常量
- OFFSET（到保存返回地址的填充长度）
- POP_RAX（sigreturn 号需要）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
