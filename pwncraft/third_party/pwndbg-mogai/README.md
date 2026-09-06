# pwndbg-mogai Fork

This directory vendors the complete Python source package from upstream
Pwndbg `2026.07.29` and applies a deliberately narrow fork layer.

- upstream tag: `2026.07.29`
- upstream commit: `f4de22244b7e9f0aeda26a92208c42edaca2f8d8`
- fork/command version: `2026.07.29-pwndbg-mogai.16` / `pwndbg-mogai`

The only upstream hooks are:

1. `pwndbg.commands.load_commands()` calls `pwndbg.pwncraft.install()` after the
   complete upstream registry has loaded.
2. `pwndbg.ui.banner()` asks the localization layer for the native Context
   title while retaining the upstream Pwndbg theme and renderer.

`launcher.sh` runs the source fork with the pinned portable runtime.  It does
not patch the installed site-packages directory.
