# Pwn 语义识别训练汇总（2026-09-12）

## 本轮覆盖

| 样本 | 主要类型 | 运行时确认 | 关键链状态 |
|---|---|---|---|
| baihu/Pwn-01 | 菜单堆 | 已完成历史验证 | 堆利用链已沉淀 |
| baihu/Pwn-02 | 自定义 allocator/残留泄漏 | 已完成历史验证 | stale-data blocked/candidate |
| qinglong/Pwn-2 | 32 位栈溢出 | ret2system 已确认 | stack-overflow-to-system candidate |
| qinglong/Pwn-4 | 菜单堆 UAF | delete→edit 别名已确认 | heap-uaf-control candidate |
| Semis/cardmaster | 整数/除零/栈越界 | suit_count=0→SIGFPE 已确认 | input-division-dos runtime_proven |
| zhuque/Pwn2/xyzcrypt | RSA 文件管理器 | 暂无 | strcat/UAF/边界均 blocked/candidate |
| Semis/jitlover | Rust JIT/BPF | 定点分析待继续 | verifier/JIT 执行面 blocked |
| Generic_kernel_shellcode | 内核 shellcode | 初筛进行中 | 以内核 ROP/权限链为主 |

## 结果指标

- 当前专项回归：98 passed。
- 已将运行时证明纳入自动扫描 `summary.confirmed`。
- 已修复语义 finding 注入顺序，UAF 证据现在可驱动利用链编排。
- 已增加不可达除零抑制，减少硬编码常量导致的误报。

## 训练改进方向

1. JIT/内核样本使用 DWARF、符号和入口函数定点扫描。
2. 对 `candidate → runtime_proven → validated` 建立统一状态升级规则。
3. 堆画布联动生命周期节点：alloc、free、stale-read、stale-write、alias。
4. 将 libc 版本、seccomp 禁用 syscall、CET/RELRO/Canary 自动作为链路前置条件。
