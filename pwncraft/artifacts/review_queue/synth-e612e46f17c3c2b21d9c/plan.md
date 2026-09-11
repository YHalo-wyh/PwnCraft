# 合成计划 · ret2libc

- 策略：ret2libc（GOT 泄漏 → libc 基址 → system）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\greatwall\HeroEditor\game`  sha256=`eac1d39474d57d07b5dc103f64e495c3c8913568bc06b3f51e6595944cf97be3`
- 保护：PIE=ON NX=ON CANARY=ON RELRO=FULL
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
- puts@plt=0x1060
- printf@plt=0x10c0
- write@plt=0x1080
- printf@got=0x4f90
- puts@got=0x4f60
- read@got=0x4fa8
- strlen@got=0x4f78
- write@got=0x4f70

## 未解析常量
- OFFSET（到保存返回地址的填充长度）
- PUTS_LIBC（libc puts 偏移）
- SYSTEM_LIBC（libc system 偏移）
- BINSH_LIBC（libc /bin/sh 偏移）
- POP_RDI（gadget shelf 未证明）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
