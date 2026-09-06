# pwndbg-mogai Fork 维护说明

## 两套调试器并存

Pwn宝只启动 `~/.local/bin/pwndbg-mogai`。用户原来的 `pwndbg`、`.gdbinit`、配置、缓存、插件和更新方式不参与安装或启动，详见 `PWNDBG_MOGAI_ISOLATION.md`。

项目 Fork：`third_party/pwndbg-mogai/`。WSL 安装后可脱离 GUI 独立运行：

```bash
pwndbg-mogai ./chall
```

GUI 通过同一命令启动，仅增加 `PWNBAO_BRIDGE=1` 与外层 `pty_relay.py`。颜色仍由 Pwndbg Theme 产生；Embedded Terminal 只忠实渲染 ANSI，并使用高对比经典 xterm palette。

## Upstream rebase

1. 对照 `UPSTREAM_COMMIT` 更新 vendored `pwndbg/`。
2. 重新应用 `pwndbg/commands/__init__.py` 和 `pwndbg/ui.py` 两个窄 hook。
3. 保留 `pwndbg/pwnbao/`、`launcher*`、`input_proxy.py`。
4. 运行 `tests/test_pwndbg_fork_v013.py`、命令 registry、独立/Embedded PTY 性能审计。
