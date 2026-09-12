# 网鼎杯 zhuque/Pwn2（xyzcrypt）自动识别训练报告

## 当前结论

该题是 PIE + Full RELRO + Canary + NX + SHSTK/IBT 的 RSA 文件管理器。当前完成静态自动识别，尚未将任意漏洞升级为运行时确认或 RCE。

## 静态识别

- `strcat@plt` 在 `0x17bb`、`0x19d8` 出现，无长度限制；需结合目标缓冲区容量和文件名可控性复核。
- `fgets(..., 0x1000)` 两处读取到约 `0x1018` 栈缓冲，静态边界检查通过，不能直接判定溢出。
- 存在 `realloc`、间接调用和对象生命周期访问，语义层标记 UAF 候选；目前缺少释放后再次使用的跨函数运行时证据。
- 自动报告共 13 条：high 4、medium 4、info 5，confirmed=0。

## 利用链状态

- `heap-uaf-control`：candidate/待验证。
- `fixed-value-pointer-write`：blocked，需证明写入目标受输入控制。
- `custom-input-loop`：blocked，需确认输入终止条件和目标对象容量。
- 无充分证据生成 ret2libc、ROP 或直接命令执行链。

## 训练价值

该样本用于检验语义识别的两个抑制条件：

1. 不能因 `strcat` 或大长度 `fgets` 单独误报 confirmed overflow。
2. 不能因 PIE/Full RELRO 下存在间接调用就误报函数指针劫持。

后续优先补充：文件名超长输入、加密/解密前后文件状态切换，以及 realloc 后旧指针是否继续进入 `strncpy/strcat` 的运行时探针。
