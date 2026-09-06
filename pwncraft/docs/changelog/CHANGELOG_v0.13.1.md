# v0.13.1

- 官方 `pwndbg` 与 `pwndbg-mogai` 完全并存：独立 command/source/runtime/config/cache/data，GUI 只调用 mogai。
- 修复冻结 EXE 启动 `wsl.exe` 时继承 `_MEI` DLL 搜索路径导致的 `0xc0000142`。
- Embedded Terminal 改为经典高对比 Pwndbg/xterm ANSI palette 和黑色背景，保留 upstream Theme 语义。
- Chunk 禁止左右/角点自由缩放，只保留底部物理 extent handle；向下拖动写真实 size 并重建 overlap。
- `+` 改为逐行展开 Chunk 内真实 user bytes，下面 Chunk 同步下移，不写内存、不扩张 Chunk。
