# 合成计划 · ret2libc

- 策略：ret2libc（GOT 泄漏 → libc 基址 → system）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_fmtstr`  sha256=`f2e24de2094b956234775e5ec3e1ae09916c7adbfeab9c161d29a12a0032d8db`
- 保护：PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL
- 往返自检：ROUND_TRIP_CLEAN（ERROR 0 条）
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
- printf@plt=0x401070
- printf@got=0x404008

## 未解析常量
- OFFSET（到保存返回地址的填充长度）
- PUTS_LIBC（libc puts 偏移）
- SYSTEM_LIBC（libc system 偏移）
- BINSH_LIBC（libc /bin/sh 偏移）
- POP_RDI（gadget shelf 未证明）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
