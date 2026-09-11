# 合成计划 · ret2plt

- 策略：ret2plt（system@plt）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_x86_vuln`  sha256=`dd0b2e4a1c25bb80ed9475ebf812c71f791889a36cc89b5248d6caf7486a33f0`
- 保护：PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL
- 往返自检：ROUND_TRIP_CLEAN（ERROR 0 条）
- 运行时验证：NOT_RUN（未执行）

## 步骤
1. 填充到返回地址偏移
2. pop rdi; ret
3. 参数 = 壳字符串地址
4. call system@plt = 0x8049060

## 缺口
- 控制流劫持偏移未证明（需要崩溃/调试证据）

## 证据
- PLT stub 0x8049060
- 节内容扫描：/bin/sh @ 0x804a008

## 未解析常量
- OFFSET（到保存返回地址的填充长度）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
