# PwnCraft v0.13 迁移结果

## 最终边界

v0.13 补充要求否定了早期“Qt Tutor / Qt Slash Palette”方案，最终迁移如下：

| 旧实现 | v0.13 最终处理 |
|---|---|
| `pwncraft/pwndbg_ext` GUI 外挂 | 删除；能力迁入真实 Pwndbg 源码 Fork |
| `TutorRenderer` / `TutorContextModel` | 删除；默认 Context 由 Fork 原生输出 |
| Qt `CommandPalette` | 删除；`/` 交互位于 Fork 的 PTY input framework |
| GUI command catalog / mapping | 删除；候选直接投影 `pwndbg.commands.commands` |
| GUI 二次中文化/配色 | 禁止；GUI 只渲染原生 ANSI cell |
| 每次 stop 全堆扫描 | 删除；stop callback 只发 dirty/stop truth |
| Heap 纯显示修改 | 改为 PhysicalMemory → ConstraintEngine → rebuild |

## 当前数据流

```text
EXP / Runtime Observation
  -> PhysicalMemory
  -> glibc allocator + Typed Views
  -> HeapSnapshot
  -> CurrentModelSnapshot(snapshot_id, memory_revision, origin)
  -> Heap Canvas / Bins / SHOW / Inspector 一次 commit
```

```text
TerminalWidget keyboard bytes
  -> WSL pty_relay
  -> third_party/pwndbg-mogai/input_proxy.py
  -> pwndbg-mogai Fork -> GDB

Pwndbg stdout -> PTY -> ANSI cell renderer
Runtime truth -> OSC Bridge -> deferred Heap snapshot
```

## 原子化和性能

- 普通 `ni/si/x/frame/vmmap/help` 不请求 Heap 全量 snapshot。
- allocator/memory-write/signal/heap command 才 coalesce 为 90 ms 延迟同步。
- Terminal renderer 使用 pyte dirty rows + same-style ASCII run batching；CJK 严格占两个 cell。
- Canvas drag/resize 只修改 `CanvasLayoutModel`；metadata edit 只能经过 PhysicalMemory 修正链。
