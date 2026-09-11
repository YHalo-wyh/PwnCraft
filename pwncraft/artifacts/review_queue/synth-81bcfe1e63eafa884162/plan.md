# 合成计划 · ret2win

- 策略：ret2win（跳过程序内现成调用点）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_tcache_dup`  sha256=`7b2d96cd88796be7e6c001093d6d46dcac4e4738bc2c096d28f5ae098681df10`
- 保护：PIE=OFF NX=ON CANARY=OFF RELRO=PARTIAL
- 往返自检：ROUND_TRIP_CLEAN（ERROR 0 条）
- 运行时验证：NOT_RUN（未执行）

## 步骤
1. 填充到保存返回地址的偏移
2. 先落一次 ret（x86-64 16 字节栈对齐）
3. 覆盖返回地址为程序内调用点
4. 该调用点自带命令参数，无需额外 ROP

## 缺口
- 控制流劫持偏移未证明（需要崩溃/调试证据）

## 证据
- 0x401512: call system
- 参数地址 0x402031
- stack_truth=missing

## 未解析常量
- OFFSET（到保存返回地址的填充长度）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
