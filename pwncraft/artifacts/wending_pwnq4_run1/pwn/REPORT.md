# 网鼎杯 qinglong/Pwn-4 漏洞识别实测报告

## 结论

已完成“自动漏洞识别 → 利用链规划 → WSL 实机验证 → AWDP 修复思路”全流程。核心漏洞为运行时确认的跨对象 UAF：`delete(0)` 释放对象后未清理全局指针，随后同尺寸重分配使 `edit(0)` 实际改写索引 1。

## 目标与保护

- 目标：`pwn`，x86-64、PIE、Full RELRO、Canary、NX、stripped。
- 沙箱：初始化 `seccomp` 并禁止 `execve(0x3b)`、`execveat(0x142)`；因此不把 shell/execve 路线误报为已确认 RCE。
- libc：随题库提供 glibc 2.27，无 safe-linking；`__free_hook=libc+0x3ed8e8`、`system=libc+0x4f420` 仅作为后续候选目标。

## 自动识别结果

- `0x15d0` 附近 Delete：从 `0x203088 + 0x10*idx` 取指针并在 `0x167a` 调用 `free`，未清零 pointer/size 表。
- `0x168d` 附近 Edit：再次从同一 pointer/size 表取值并写入，形成跨函数悬空写。
- 语义层输出 `GLOBAL_POINTER_FREE_NO_CLEAR_CANDIDATE`，桥接层映射为 `heap_lifetime/use_after_free_candidate`。
- 除法语义候选存在，但运行时回灌证明分母是硬编码 `.data:0x203010` key 的长度 17，输入不可达；自动链路已抑制 `input-division-dos`，避免误报。

## WSL 实测证据

凭据文件必须无尾换行：`username=admin`（5 bytes）、`password=s4cur1ty_p4ssw0rd`（17 bytes）。带换行会触发 `Invalid username length`，不能作为漏洞结论。

最小复现序列：

```text
save(0,8,ABCDEFGH)
delete(0)
save(1,8,IJKLMNOP)
edit(0,WXYZ1234)
read(1) -> [1,WXYZ1234]
read(0) -> [0,WXYZ1234]
```

这证明 stale pointer 与重分配 chunk 别名均可观测。`delete(0) → read(0)` 还能读出释放块残留/allocator 元数据字节，但尚未证明为 libc 地址泄漏。

自动报告摘要：`high=2, medium=2, info=2, confirmed=2, risk_score=50`。

## 利用链状态

- `heap-uaf-control`：candidate（运行时已确认悬空写，但尚未完成函数指针/任意写控制）。
- `reallocated-stale-data-leak`：blocked（需证明可解码地址并获得后续写原语）。
- `heap-file-fsop`：blocked（需 libc 基址、FILE 写入目标和触发点；seccomp 下优先 ORW/stdio 路线）。
- 栈溢出、ret2libc、直接 shell 均无充分证据。

## AWDP patch 思路

1. Delete 成功后同时执行 `pointer_table[idx]=NULL; size_table[idx]=0`，并在 Edit/Read 前强制检查对象状态。
2. 增加对象状态位或 generation counter，拒绝 stale handle；重复 Delete 必须安全失败。
3. Save 对新分配缓冲区显式清零，避免释放块残留数据被重新读取。
4. 将 `read/write` 长度统一限制为保存尺寸，所有整数转换前做无符号范围校验。
5. 保留 seccomp 最小白名单；不要把存在 `system` 导入误判为可执行链。

产物：`auto_report.json`、`runtime_probe.json`、`awdp_patch_audit.json`、`probe.py`、`probe_read_freed.py`。
