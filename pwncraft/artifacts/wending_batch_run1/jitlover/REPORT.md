# 网鼎杯 Semis/jitlover 自动识别训练报告

## 当前结论

样本为带 DWARF 的 Rust JIT/BPF→x86 编译器，目标包含 `compile`、`verify_jmps`、`parse_raw_bytes`、`emit_cond_jump` 等关键语义。由于 ELF `.text` 约 14 MB，完整 objdump 扫描超出本轮时间预算，未将候选漏洞误报为 confirmed。

## 已确认静态事实

- x86-64 PIE、Full RELRO、NX，未发现 Canary。
- 导入 `mmap64/mprotect/munmap/realloc/memmove`，存在 JIT 可执行内存与生命周期管理面。
- 存在 BPF 指令结构和跳转验证函数 `verify_jmps`，应重点检查跳转目标截断、边界校验和生成代码权限切换。
- `parse_raw_bytes` 是外部字节流入口，`compile` 负责将 BPF 转换为机器码；当前只记录为审计重点。

## 利用链状态

- JIT 跳转越界/类型混淆：blocked，需逐指令数据流和运行时非法字节码验证。
- RWX/JIT 内存执行：blocked，仅凭 `mprotect` 导入不足以判定可利用。
- 无充分证据生成 ROP、ret2libc 或 shellcode 链。

## 下一轮优先探针

1. 从 DWARF 符号定点反汇编 `parse_raw_bytes`、`verify_jmps`、`compile`，避免全量扫描。
2. 构造最小 BPF 跳转边界样本，记录 verifier 接受/拒绝与崩溃行为。
3. 追踪 `mmap/mprotect` 权限序列，确认是否存在 W^X 违反或可控代码指针。
