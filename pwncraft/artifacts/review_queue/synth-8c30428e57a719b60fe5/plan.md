# 合成计划 · ret2libc

- 策略：ret2libc（GOT 泄漏 → libc 基址 → system）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\greatwall\chall\x\chall`  sha256=`b64e23e0271c9437744dbbe4a5f8de04dbcde5e1d9a1d6ab08ea4d225bd49eb1`
- 保护：PIE=OFF NX=ON CANARY=ON RELRO=PARTIAL
- 往返自检：ROUND_TRIP_ISSUES（ERROR 1 条）
- 运行时验证：NOT_RUN（未执行）

## 步骤
1. 泄漏 puts@got → libc base
2. 再次触发溢出
3. ret2libc：pop rdi + binsh@libc + system@libc

## 缺口
- 控制流劫持偏移未证明（需要崩溃/调试证据）
- libc 文件未提供或符号未解析（system/puts/str_bin_sh）
- pop rdi 控制 gadget 未从 gadget shelf 证明

## 证据
- puts@plt=0x402040
- puts@got=0x5d5008
- read@got=0x5d4ba0
- strlen@got=0x5d4ab8
- write@got=0x5d4a40

## 未解析常量
- OFFSET（到保存返回地址的填充长度）
- PUTS_LIBC（libc puts 偏移）
- SYSTEM_LIBC（libc system 偏移）
- BINSH_LIBC（libc /bin/sh 偏移）
- POP_RDI（gadget shelf 未证明）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
