# pwncraft v0.4.0

## HeapViz 架构

- 主 Exp 编辑器与 Heap 页共享同一个 QTextDocument，普通堆操作直接写入 EXP 后再解析，减少双文本同步和 undo 丢失。
- HeapOperation 增加 program / corruption / intent 分层。
- 新增严格校验与演示计划两种模拟模式；严格模式不允许利用意图直接“传送” allocator 状态。
- ChunkState 分离 chunk header 地址与 malloc user pointer，并增加 physical_id、provenance。
- 新增菜单 HandleState，能区分 active / dangling / alias 并跟踪物理块复用。

## allocator 状态机

- tcache / fastbin / smallbin / unsorted / largebin / top 的分配顺序更接近 glibc 常见路径。
- unsorted 支持 first-fit 复用与 remainder split；largebin 提供保守 best-fit + split。
- 普通 free 和 malloc_consolidate 支持物理相邻 coalesce；与 top 相邻时并回 top。
- glibc 2.29+ 严格模式检测普通 tcache double free，命中后标记 allocator abort 并停止后续状态伪造。
- safe-linking poisoning 只有在 freelist 节点真正被 malloc 消费后，下一次同 size 分配才会推导到 poisoned target。
- `malloc_to_target` 在严格模式改为“实际执行 malloc + 校验预期”，未命中时仍保留 allocator 的真实返回状态。

## EXP 语义

- 新增安全整数表达式引擎，支持变量、+ - * // %、移位与位运算，不执行用户代码。
- 支持从真实 UAF edit 写入中推断 tcache/fastbin poisoning，能识别 `p64(target ^ (pos >> 12))` 和 encoded_fd 变量形式。
- chunk_addr 与 user_ptr 在 safe-linking、fake chunk、定向 malloc 中统一语义。

## glibc / 利用路线

- 新增 compatibility 模块，集中描述 hooks、safe-linking、top-size check、IO vtable validation 等能力。
- House/利用路线 UI 会显示 supported / conditional / unsupported 和前置条件。
- tcache safe-linking 模板不再硬编码 `__free_hook`，改成版本无关的 `target_addr`。
- fastbin->unsorted 模板增加 guard，避免 consolidate 后整段直接并回 top。

## Pwndbg 校准

- 新增 Pwndbg 文本解析器，可读取常见 tcachebins/fastbins/smallbins/largebins/unsorted/heap 输出。
- 新增模拟 vs observed diff，按地址、size 和 bin 比较当前 step。

## UI / 其他

- 启动任务配置恢复 IO 变量名输入。
- 修复收藏代码块中失效的 `fmt_got_overwrite_i386` ID。
- 不再把代码块 tags 中零散 glibc 版本号误当作连续 min/max 范围。
- 详情面板增加 intent 状态、handle、physical_id、user_ptr、provenance 和 allocator abort 提示。
- v0.4.0 核心回归测试扩展到 28 项。
