# pwncraft v0.7.1

## Qwen Heap Rule Catalog

- 新增受限、声明式 Heap Rule Catalog，覆盖基础操作以及 safe-link、header overflow、fd poisoning、fake chunk、consolidate 等校正入口。
- Qwen 只能返回规则 ID 和参数；程序确定性展开为 HeapOperation，再执行字段校验、源码锚点校验和独立 allocator replay。AI 不能直接改 chunk、bin 或画布。
- 兼容 Qwen 将 arguments 返回为对象或按 catalog 参数顺序排列的数组；未知规则、未知参数和缺少必需事实均直接拒绝。
- Heap IR 等价比较会归一化整数和纯字面量，`0x90 -> 144`、`b'A' -> b"A"` 不再被误认为可学习的语义校正。

## WriteUp 语料闭环

- 新增本地 PDF WriteUp 扫描器：锁定文件 SHA256、按题分页、修复常见 PDF 行号/缩进噪声，只输出能通过 AST 的派生 Python case，不复制原 PDF。
- 新增可恢复 corpus CLI 和严格反馈编译器；成功候选自动保存最小回归 fixture、snapshot review 和规则来源。
- 全局规则晋升继续要求两个独立 case、零已审核负样本和 holdout 通过；题目特有或高级 corruption 事实只保留为 fixture/场景证据。

## 静态识别

- 默认 helper 名大小写不敏感，支持 `Alloc/Add/Free/Fill/Dump` 等常见写法。
- 有界内联 `pwn/exploit/attack/solve/exp/main` 入口及常见重连循环一次，不执行 EXP，也不会无限展开。
- 修复菜单 helper 同时包含 `recvuntil` 与 `sendline` 时被误判成纯接收解析器的问题；`create_heap/edit_heap/delete_heap` 现可按签名稳定生成 IR。
