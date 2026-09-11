# 合成计划 · ret2win

- 策略：ret2win（跳过程序内现成调用点）（status=blocked）
- 目标：`F:\pwn宝\pwncraft\artifacts\gw-training\intelpwn\challenge_pie`  sha256=`9f5e8ae9f4b3df9b5098ef6f789ad1bbb4450ad52997abf4538784eb1ecb45ef`
- 保护：PIE=ON NX=ON CANARY=OFF RELRO=PARTIAL
- 往返自检：ROUND_TRIP_CLEAN（ERROR 0 条）
- 运行时验证：NOT_RUN（未执行）

## 步骤
1. 填充到保存返回地址的偏移
2. 先落一次 ret（x86-64 16 字节栈对齐）
3. 覆盖返回地址为程序内调用点
4. 该调用点自带命令参数，无需额外 ROP

## 缺口
- 控制流劫持偏移未证明（需要崩溃/调试证据）
- PIE 已开启但无基址泄漏事实

## 证据
- 0x1190: call execve
- 参数地址 0x2017
- stack_truth=missing

## 未解析常量
- OFFSET（到保存返回地址的填充长度）

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
