# Pwn宝 v0.11.0 Validation

## 结果摘要

- Windows Python 3.11 / PyQt5：`204 passed, 1 skipped in 24.90s`。
- Ruff：`All checks passed!`
- PyInstaller one-file build：`dist/pwn宝.exe`，42,400,262 bytes；8 秒启动 smoke 期间保持运行且无 stderr。
- Heap semantic benchmark：`60/60`，whole-case pass rate `100%`，19 项 metrics 均 `100%`。
- Sunshine real corpus：52 份。`PARSE_ONLY 9 / MODEL_READY 2 / PARTIAL_REPLAY 18 / FULL_REPLAY 23 / SEMANTIC_VERIFIED 0`。
- MODEL_READY-or-better：`43/52 = 82.69%`。未到 90%；9 份主要依赖远程 socket 响应、服务端隐式 malloc、动态 iterable 或动态 runtime entrypoint，不把 unknown 伪造成 allocator IR。

## 复现命令

```bash
'/mnt/d/HermesAgent/hermes-agent/venv/Scripts/python.exe' -m pytest -q
'/mnt/d/HermesAgent/hermes-agent/venv/Scripts/python.exe' -m ruff check .

'/mnt/d/HermesAgent/hermes-agent/venv/Scripts/python.exe' \
  -m pwnbao.tools.heap_semantic_benchmark --json \
  > artifacts/semantic_v011.json

'/mnt/d/HermesAgent/hermes-agent/venv/Scripts/python.exe' \
  -m pwnbao.tools.sunshine_ast_corpus \
  'C:\Users\WYH\Desktop\sunshine 附件' \
  --output artifacts/sunshine_ast_v011
```

## 真 PTY、resize 与 Ctrl+C

`artifacts/runtime_probe_v011/pty_probe.txt`：

```text
INITIAL True True 24 80
RESIZED True True 41 132
```

两个 `True` 分别是 child stdin/stdout `isatty()`。数据不来自 GUI 推测。

`artifacts/runtime_probe_v011/ctrl_c.txt` 包含：

```text
Program received signal SIGINT, Interrupt.
```

之后再次出现 `pwndbg>`，证明 ETX 通过 slave PTY 中断 inferior，而不是杀死 GUI relay。

`artifacts/runtime_probe_v011/readline.json` 的真实 Pwndbg 会话证明 `tcacheb<Tab>` 由 Readline 补全为 `tcachebins`，且 `↑` 恢复并再次执行上一条 `show pagination`。

## 真 Pwndbg Extension / Frame Inspector

实测使用 pinned portable Pwndbg：

```text
$HOME/.local/share/pwnbao/pwndbg/2026.07.29/bin/pwndbg
```

`artifacts/runtime_probe_v011/probe_summary.json` 记录两个由同一 C harness 编译的 binary：

- `-O0 -fno-omit-frame-pointer`：`vuln -> caller foo + 25`，`rbp_role=frame_pointer`，saved RIP 等于 unwinder return target。
- `-O2 -fomit-frame-pointer`：`vuln -> caller foo + 9`，`rbp_role=general_register`，`saved_rbp/saved_rip=null`。
- 两次均解码 15 个 OOB 消息，包含 handshake/catalog/stop/frame/heap/prompt/session。

Large command catalog 改为从 extension 直接向 PTY 单调 write，避免 Pwndbg before-prompt hook 在 base64 frame 中插入 bracketed-paste 字节。实测 9/9 OSC frames 完整解码，visible stream 无 `PWNBAO` 泄漏。

## 官方 Pwndbg 无损

`artifacts/runtime_probe_v011/official_commands.txt` 是真 glibc heap harness 在 `marker` breakpoint 上的实际终端记录，顺序执行：

```text
context
tcachebins
fastbins
bins
heap --count 8
vis-heap-chunks 4
vmmap
telescope $rsp 4
checksec
cyclic 32
```

无 `Undefined command` / Python traceback。Tutor 没有覆盖任何一个名称。

## Extension failure fallback

`artifacts/runtime_probe_v011/extension_failure_fallback.json`：故意 `source /definitely/missing/pwnbao.py` 后，同一会话仍出现官方 `pwndbg>` 并能执行 help。

## AArch64 GDB assertion 回归

针对 `httpd` (`ELF64 AArch64`, interpreter `/lib/ld-linux-aarch64.so.1`) 实测 `artifacts/runtime_probe_v011/aarch64_static_safe.json`：

- ELF 架构识别为 `aarch64`，`auto_start=false`；
- Pwndbg prompt 正常出现，`show architecture` 为 AArch64；
- 不再出现 `i387_supply_xsave` / `A problem internal to GDB`；
- `-iex` 在读取 ELF 前关闭 debuginfod，不再出现 `Downloading separate debug info ... Invalid argument`；
- `info files` 能完整列出 AArch64 ELF sections。

## UI audit

`artifacts/ui_audit_v011/` 内 6 张 `1600×1000` PNG：

```text
pwndbg_tutor_idle.png
pwndbg_tutor_slash_palette.png
pwndbg_tutor_frame.png
pwndbg_tutor_frameless.png
pwndbg_tutor_operation_history.png
pwndbg_tutor_heap_chunk.png
```

快照确认：没有命令发送框/发送按钮；Slash Palette 在 terminal 内；terminal/right panel 约 75/25；顶部按钮紧凑；默认没有 live diff；文本不截断。

## 仍存限制

1. Windows 主路径依赖 WSL2，尚未实现 native Windows ConPTY transport。
2. pyte 对部分非标准 terminal extension 仅做宽容降级；复杂 CJK 组合字形不保证与所有 terminal 完全像素一致。
3. 真 reverse execution 由用户通过原生 GDB `record full` 启用；当前没有未经验证的图形“反向”按钮。
4. Sunshine corpus 仍为 82.69%，而不是伪 90%。`SEMANTIC_VERIFIED=0`；runtime bridge 已能产生外部 snapshot，但 corpus case 还缺与同 binary/libc/checkpoint 绑定的 oracle sidecar。
