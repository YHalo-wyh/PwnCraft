# pwndbg-mogai 与官方 Pwndbg 并存边界

## WSL 目录

```text
官方 Pwndbg（Pwn宝只读、不修改）
  command: command -v pwndbg
  config/cache/source: 用户原有位置

Pwn宝魔改版
  command: ~/.local/bin/pwndbg-mogai
  root:    ~/.local/share/pwnbao/pwndbg-mogai/2026.07.29-pwndbg-mogai.16
  source:  <root>/source
  runtime: <root>/runtime
  config:  ~/.config/pwnbao/pwndbg-mogai
  cache:   ~/.cache/pwnbao/pwndbg-mogai
  data:    ~/.local/share/pwnbao/pwndbg-mogai/data
```

安装器不会写入 `command -v pwndbg`、`~/.gdbinit`、`~/.config/pwndbg` 或官方源码目录。`pwndbg-mogai` 固定使用 `-nx`，并设置独立 XDG/GDB history 路径；GUI 也只调用该命令。

## 0xc0000142 修复

PyInstaller one-file 进程启动系统 `wsl.exe` 前调用 `SetDllDirectoryW(None)`，清除 `_MEI` 私有 DLL 搜索目录，避免 WSL 错误加载打包目录 DLL。入口：`pwnbao/core/external_process.py`。这只修复 Windows 子进程装载环境，不改 WSL 内部状态。

## 本机验证证据

`artifacts/ui_audit_v013/pwndbg_mogai_isolation.json` 记录官方命令路径/哈希和 mogai 独立目录。当前官方 `/home/wyh/bin/pwndbg` SHA-256 在安装前后均为：

```text
06cf47591ac8a0538b1f38dbc18c3eb0e677dfcc855f3fb194d1f67443706050
```
