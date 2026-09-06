# 分领域边界清单 (M5 泛化与稳定)

日期: 2026-09-06。本清单按领域分别列出已解决、未解决和已曝光范围。

## 已曝光案例集合

以下案例已用于修复或探测，其结果不再视为全新盲测：
babyheap, lab13, note2, wheelofrobots, hacklu, stkof

## 堆 (heap)

### 已解决

| 能力 | 证据 | 规则/修订 |
|---|---|---|
| PROMPT_SYNC ≠ OUTPUT_DATA_FLOW | cycle-1 synthetic 7 tests | r3 |
| free/show/delete/edit 语义 (index-only + structural) | lab13 4 helper 全 MATCH | r3 |
| clear-pointer (POST_FREE_NULL_STORE) | lab13 source .c L113 | r3 |
| 1:N allocator events (BinaryIR xrefs) | test_heap_domain_1n | r5 |
| 调用点级 OUTPUT_DATA_FLOW (show/shownote) | cycle-3 | r5 |
| 三参数 (index/choice/data) 识别 | note2 editnote | r5 |
| Python 2 方言解析 | cycle-2 source_compat 8 tests | r4 |

### 未解决

| 缺口 | 影响 | 阻塞原因 |
|---|---|---|
| size-only alloc 契约 (allocate(size)) | babyheap/stkof alloc 语义 unknown | 需 prompt→size 数据流从调用点回传 |
| editnote 三参 choice 子菜单 | 中间参数角色非标准 (submenu) | 需子菜单语义模型 |
| delete second-free (struct chunk) | TARGET_BEHAVIOR 2≠1 | 引擎需支持 free-by-physical-id |
| edit 的 size+1 off-by-one 传播 | BINS 层断言需引擎支持 | 引擎 edit 长度覆盖边界未实现 |
| canvas inv7 top-chunk overlap | 依赖 delete 1:N 建模 | 同上 |

### 已曝光范围

babyheap, lab13, note2 的 EXP 与 source 已用于规则修复与探测。
这些题的后续结果不视为全新盲测。

## 栈 (stack_rop)

### 已解决

| 能力 | 证据 |
|---|---|
| EXP_LEAK_001/002 (u64/u32 短读) | synthetic 4 tests |
| EXP_LEAK_003 (recvline 未知长度) | synthetic 1 test |
| EXP_LEAK_004 (未使用 recv 结果) | synthetic 2 tests |
| EXP_ARCH_001/002 (p32/p64 架构截断) | synthetic 2 tests |
| EXP_PIE_001 (PIE 硬编码地址) | synthetic 1 test |
| 栈布局收集 (canary/帧/槽位) | 23/24 案例布局 OK |
| 字节范围 (ExploitIR recv/send 交互) | 39 条 byte_ranges |
| 给定状态 (帧大小/槽位摘要) | 108 条 given_state |

### 未解决

| 缺口 | 影响 |
|---|---|
| ROP 链追踪 (gadget 序列语义) | 需 BinaryIR CFG 层 |
| ret2libc 参数恢复 (syscall ABI) | 需 syscall 模型 |
| SROP 信号帧识别 | 需 sigcontext 布局知识 |
| canary 值泄露路径分析 | 需数据流到 canary 槽位的映射 |

### 已曝光范围

brop, ret2dlresolve (×2), ret2libc (×2), fake_frame, partial_overwrite,
stacksmashes, ret2shellcode, rop — 全部布局断言 OK，无真实失败记录
(栈课程 3 尚未建立负例断言)。

## fmt (格式化字符串)

### 已解决

| 能力 | 证据 |
|---|---|
| EXP_PARSE (语法检查) | synthetic 2 tests |
| FMT_INTERACTION (交互提取) | test_m1 |
| FMT_SEMANTIC_CHECKS (%n 写 / 位置参数 / 转换计数) | fmt_semantics.py + test_m1 f1 |

### 未解决

| 缺口 | 影响 |
|---|---|
| fmtstr_payload 自动构造 | 需要栈布局 + 偏移计算 |
| 写什么写哪里 (GOT/返回地址) | 需 BinaryIR 调用目标分析 |
| leak 格式串解析 (%p/%s 值推导) | 需运行时反馈或符号执行 |

### 已曝光范围

CSAW-contacts, CCTF-pwn3, blind_fmt_got, blind_fmt_stack, leakmemory,
overwrite — 全部 MATCH (smoke 层)。fmt 语义层未在这些题上做深度分析。

## 指标 (阶段 4 拟议目标, 非当前实测)

| 指标 | 当前状态 |
|---|---|
| 必需断言完成率 | truthregress 2 案例 100% (4/4 必需层) |
| 已接受断言回归率 | truthregress exit 0 = 100% |
| UNKNOWN 率 | editnote 1 条 (note2); allocate 1 条 (babyheap); 共 2 条已记录 |
| 精确率/召回率 | 待阶段 2 课程建立足够正例+反例后统计 |
| 无依据确认 | 0 (所有确定结论均带 evidence) |
