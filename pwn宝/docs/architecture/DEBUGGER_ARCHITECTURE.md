# Pwn宝 v0.13.2 pwndbg-mogai 架构

## 固定 Fork

- 项目目录：`third_party/pwndbg-mogai`
- upstream release：`2026.07.29`
- upstream commit：`f4de22244b7e9f0aeda26a92208c42edaca2f8d8`
- fork version：`2026.07.29-pwndbg-mogai.16`
- WSL command：`~/.local/bin/pwndbg-mogai`

## 并存与启动

```text
官方 pwndbg ── 用户原命令/配置/插件/更新，Pwn宝不读取不修改

Pwn宝 -> frozen DLL boundary reset -> wsl.exe
      -> pty_relay.py -> pwndbg-mogai
      -> isolated source/runtime/XDG config/cache/data
      -> GDB + Pwndbg upstream + mogai native extensions
```

Launcher 固定 `-nx`，不会加载用户官方 `.gdbinit`。GUI 不做字符串翻译、Tutor 二次渲染、命令 catalog 或 Slash mapping。Bridge 只传 runtime truth。

## 颜色

Context/nearpc/telescope 等 ANSI 由 Pwndbg Theme 生成；Terminal Renderer 保留 256/truecolor，并把 named ANSI 映射到经典高对比 xterm palette：CODE red、HEAP blue、STACK yellow、DATA purple、banner blue。

## 性能

PTY 输出直接进入 dirty-row renderer；普通 `ni/si` 不触发全堆扫描。allocator dirty/signal/显式 heap 命令才异步请求 snapshot。
