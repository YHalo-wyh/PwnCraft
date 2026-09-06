# v0.9.1 Validation

## Windows 全量回归

Windows Python 3.10 + PyQt5 offscreen：

```bat
set QT_QPA_PLATFORM=offscreen
D:\python310\python.exe -m unittest discover -s tests -q
```

结果：`Ran 166 tests / OK`。命令原始结果保存在 `artifacts/semantic_benchmark/tests_windows_v091.txt`。

该轮重点验证：

- 详细画布不生成 `payload:` 概要；机器字来自 `PhysicalMemory`。
- 已知非零字节全部展开，unknown 尾部按精确 byte offset 标记，不显示 NULL。
- 窄视口中 alloc/free 不改变现有 chunk 的纵向位置；bin 放在物理堆之后且不用穿过 chunk 的长连线。
- 双链节点完整显示 `arena`/chunk ID/ `bk`/ `fd`，不对节点名省略。
- doubly refresh 不会撤销程序对 fd/bk 的写入。
- fastbin/smallbin tcache refill、largebin nextsize 环和每步 `BinTransitionEvent`。

WSL Python 3.12 全量 discover 结果：`Ran 166 tests / OK (skipped=33)`；33 项为当前 WSL 没有 PyQt5 时按设计跳过的 GUI 用例。

## Ground-truth semantic benchmark

```bash
python -m pwnbao.tools.heap_semantic_benchmark
```

数据集：`datasets/semantic_benchmark/v0.9.1.json`，12 个 case。

| Metric | Result |
|---|---:|
| Operation Precision | 100% |
| Operation Recall | 100% |
| Operation F1 | 100% |
| Argument Accuracy | 100% |
| Payload Span Accuracy | 100% |
| Write Range Accuracy | 100% |
| Overwrite Field Accuracy | 100% |
| Allocator Checkpoint Accuracy | 100% |
| Bin Membership Accuracy | 100% |
| Field Value Accuracy | 100% |
| Bin Transition Accuracy | 100% |
| Whole Case Pass Rate | 12/12, 100% |

机器可读报告：`artifacts/semantic_benchmark/v091_report.json`。  
人类可读结果：`artifacts/semantic_benchmark/acceptance_v091.txt`。

12 个 case 在 v0.9.0 的 normal/overflow/off-by-one/tcache poison/safe-linking/overlap/ROP/flat 基础上，增加：

1. fastbin 分配后 refill tcache；
2. smallbin tail 分配后 refill tcache 与顺序；
3. largebin 不同 size 代表的 nextsize 环；
4. UAF 破坏 doubly link 在 refresh 后仍保留。

## UI 截图验收

- `artifacts/ui_audit/heap_physical_overwrite_v091_windows.png`
- `artifacts/ui_audit/canvas_physical_overwrite_v091_windows.png`
- `artifacts/ui_audit/overwrite_inspector_v091_windows.png`
- `artifacts/ui_audit/canvas_bins_v091_windows.png`
- `artifacts/ui_audit/heap_bins_v091_windows.png`

截图从 Windows Qt 实际渲染生成，覆盖物理 overflow 与 largebin 双链。画布中 A/B 内容、B.prev_size/B.size 和 arena/chunk fd/bk 节点均为当前 replay 证据，不是为演示填充的虚构 payload。

## 仍保留的边界

- 这是面向 CTF 可观测行为的 glibc 子集，不是完整 malloc.c 执行器。
- largebin size representative/nextsize 使用保守模型；与特定 libc 版本内部细节冲突时，以 Pwndbg 校准的实际内存为准。
- 无源码字节、allocator 写入或调试器观测证据的区域始终保持 unknown。
