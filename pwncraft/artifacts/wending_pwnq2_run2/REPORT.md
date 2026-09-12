# 网鼎杯 qinglong/Pwn-2 漏洞识别实测报告

- 目标：short，32 位 i386，No PIE、No Canary、NX、Partial RELRO。
- 登录前置：用户名 admin、密码 admin123。

## 自动识别

- vuln 中 read(0, ebp-0x50, 0x58)：静态确认覆盖保存返回地址，偏移为 88 字节。
- gift@0x80485e6 直接调用 system@plt；.rodata 含 /bin/sh。
- 现有扫描结果：critical 2、high 2、info 9；关键 confirmed 为栈溢出。
- printf 的 %p 位于固定格式串中，不判定为格式化字符串漏洞。

## 利用链与 WSL 实证

admin/admin123 登录后发送 88 字节填充 + gift 地址，链路进入 system。通过 pwntools 在 WSL 实测 echo PWN_OK，稳定得到 PWN_OK，记录见 runtime_probe.json。

利用链状态：stack-overflow-to-system 已具备运行时证据；传统 ret2libc/ret2csu 不需要，因为目标存在固定地址的 gift 和 /bin/sh。

## AWDP patch 思路

1. 将 read 长度从 0x58 限制为不超过 0x50。
2. 删除或隔离 gift→system，命令执行改为固定白名单。
3. 开启 PIE、Stack Canary、Full RELRO，并移出明文凭据。
4. 发布构建移除 %p 地址回显。

结论：这是已验证的 32 位 ret2win/ret2plt 风格链，非候选误报。
