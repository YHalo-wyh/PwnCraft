# 合成计划 · none

- 策略：none（status=none）
- 目标：`F:\pwn宝\pwncraft\artifacts\greatwall\SomeMin\pwn`  sha256=`8ba3ed4859a00c78f0d83b28a7af0e875d9420c33ee1b28ab3e76a4f4716f2f3`
- 保护：PIE=ON NX=ON CANARY=ON RELRO=FULL
- 往返自检：NO_STRATEGY（ERROR 0 条）
- 运行时验证：NOT_RUN（未执行）

## 步骤

## 说明
- 未产生候选策略：静态事实不足（见 gap 节点），本 case 作为负样本沉淀。

## 纪律
- 生成物为 DERIVED 级别：只能作为骨架，必须人工复核。
- 未通过运行时验证前，`trainable=false`，不得进入训练/评测 split。
