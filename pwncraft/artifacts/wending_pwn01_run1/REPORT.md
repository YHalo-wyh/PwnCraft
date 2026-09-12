# 网鼎杯 Pwn-01 漏洞识别实测报告

- 样本：baihu/Pwn-01.zip；ELF：pwn（x86-64 PIE，未 strip）
- libc：libc-2.31.so
- SHA256：b5fff4461506cf6c25fe3fbfed053c7873c465e0f4c362a980d2ba060fda6e2b

## 自动识别

- 统一风险 7 项：high 1、medium 1、info 5；静态 confirmed=0。
- 保护：PIE/NX/CANARY/FULL RELRO 开启，FORTIFY 关闭。
- 语义层识别到 ALLOCATE_OBJECT、FREE_OBJECT、READ/WRITE_OBJECT、NARROWING_CONVERSION、SIGNED_BOUNDS_CHECK、INDEX_CHECK_NOT_OBSERVED、CALL_INDIRECT。
- WSL ROPgadget v7.7：pop rdi=0x1763、pop rsi=0x1761、ret=0x101a，并解析多寄存器 pop 序列。

## 关键证据

- delete_chunk free 后清零指针，未形成直接 UAF。
- show_chunk 使用用户 index 读取 ptr[index]，边界可达性需运行时确认。
- edit_chunk 只允许一次，读取 8 字节地址后写入固定值 0xa2c2a，形成一次性任意地址固定值写原语。
- scanf 入口仅作为复核线索，不能单凭导入名判定漏洞。

## 利用链规划

- integer-boundary-bypass：blocked，缺少索引/长度到内存访问的跨块数据流证明。
- custom-input-loop：blocked，缺少输入终止条件与目标对象容量证明。
- input-to-output-leak：blocked，缺少可观测地址到控制原语验证。

PIE + Full RELRO + Canary 下未误报传统 GOT 覆盖或无泄漏 ret2libc。下一步优先验证一次性固定值写的目标（函数指针/堆元数据）以及负索引/超界索引可达性。

## 第二轮训练与 WSL 实证

- 识别器新增 array_index_unchecked：要求已知全局数组容量、比例寻址、输入来源且缺少关联 guard。
- 新链 unchecked-indexed-pointer-table 会保留相邻槽位布局、有效指针、ASLR 泄漏缺口，不将崩溃误称 RCE。
- 交互式 WSL 探针避免 scanf/read 的 stdio 预读干扰：show(0) 成功回显 NORMAL_MARKER；show(32) 和 show(-1) 都打印 Index 后以 SIGSEGV（exit 11）结束，没有边界拒绝。

## AWDP patch 思路

1. edit_chunk 改为白名单字段写入；增加地址范围、对齐和目标对象校验。
2. 所有 index 统一检查 0 <= index < 0x20，并限制到当前已分配槽位。
3. 尺寸限制上限并检查 read 返回长度，拒绝未初始化整数。
4. 使用 patch_preview 先确认字节范围、原始哈希和回滚路径，再应用补丁。

## 验证

WSL Ubuntu-24.04 实测 ROPgadget 可用，目标可启动进入菜单；本阶段仅做静态分析与启动 smoke test，没有把进程启动当作利用成功。原始与派生证据保存在 objdump.txt、auto_report.json、awdp_patch_audit.json。
