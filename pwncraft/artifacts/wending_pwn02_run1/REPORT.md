# 网鼎杯 Pwn-02 漏洞识别实测报告

- 样本：`baihu/Pwn-02.zip`；目标：`safenote`（x86-64 PIE，stripped）
- 依赖：`libsafelib.so` 自定义 allocator、`libc-2.31.so`

## 自动识别与语义增强

- 第二轮扫描：critical 0、high 0、medium 0、info 10，confirmed 0。
- 语义层已将导入的 `pMalloc/pFree` 归一为 `ALLOCATE_OBJECT/FREE_OBJECT`，并标记 `CUSTOM_ALLOCATOR_API`；不会因导出名直接推断 UAF。
- 保护：PIE/NX/CANARY/FULL RELRO 开启，FORTIFY 关闭。

## 关键静态证据

- 主程序维护 32 个 slot（`0x40a0 + 0x10*i` / `0x40a8 + 0x10*i`），create/write/read/delete 均检查 `0 <= idx <= 31`，删除后清零两张表。
- `libsafelib.so!pMalloc` 实现独立 allocator：16 字节对齐、max_fast=0x80、safe-linking 单链；`pFree` 有范围/链表校验。
- 尺寸存在高位标志处理：create/read 使用 `0x80000000`，write 使用 `0x08000000`。这是明确的逻辑缺陷候选，不等同于内存破坏。
- `pMalloc` 对 `0x80000000..0xffffffdf` 的无符号上限检查与后续 `cdqe` 符号扩展不一致；`size=2147483648` 实测快速 `exit(0)`。当前按 DoS/拒绝服务候选记录，尚无 RCE 证据。
- 加密变换函数对用户 salt 长度执行 `idiv`，静态未见零值保护；`salt=0` 是待验证 SIGFPE/DoS 候选，不计入 confirmed。

## WSL 运行时实证

分阶段发送 `tester → create(0,16,enc=1) → write(0,16,ABCDEFGHIJKLMNOP) → read(0,key,salt)`，目标正常返回菜单，但 read 输出为乱码而非原文；与掩码不一致静态证据相互印证。未观察到崩溃、越界拒绝缺失或 RCE。

补充 fastbin 实测：`create(size=32) → write → delete → create(同尺寸) → read` 可读出前一对象残留 payload；未覆盖时前 8 字节还可能是 safe-linking 编码的 fd。该项归类为 `uninitialized_reallocated_chunk_read` / `stale_reallocated_data`，可形成堆地址泄漏候选，但尚未连接到任意写或控制流劫持。

## 利用链规划

- `heap-uaf-control`：blocked；应用层 delete 清槽，未证明悬挂指针。
- `heap-file-fsop`：blocked；仅有 libc 版本信息，缺少 FILE 覆写目标与可控写原语。
- `reallocated-stale-data-leak`：blocked；残留数据泄漏已由运行时复现，但缺少地址解码稳定性和后续可控写原语。
- `integer-boundary-bypass`：blocked；索引有显式有符号边界检查，尺寸高位仅形成逻辑分支差异。

## AWDP patch 思路

1. 把加密标志定义为单一常量（`0x80000000`），修正 write 分支并增加明文/加密双向回归。
2. 在 `pMalloc` 入口拒绝会被 `cdqe` 符号扩展的超大请求，统一使用 `size_t` 检查和溢出保护。
3. 保持 slot 的 0..31 与删除清零不变，并在库 API 边界增加对象状态断言。

原始 ELF、反汇编、扫描 JSON 与补丁审计均保存在本目录；当前结论严格区分静态证据、运行时证据和待验证缺口。
