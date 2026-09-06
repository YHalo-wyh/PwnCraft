# CHANGELOG v0.11.0

## Integrated Pwndbg Tutor Terminal

- 用 WSL `pty.fork()` controlling TTY + Qt 字节 transport 替换伪终端，删除命令 QLineEdit 和“发送”按钮。
- 新增 pyte ANSI screen、自绘 TerminalWidget、Readline 键位、Ctrl+C、resize、UTF-8 和 scrollback。
- 新增 Qt-free Pwndbg Tutor Extension，以 versioned OSC/base64 JSON OOB 协议传递状态，官方 Pwndbg 不修改。
- `/` 命令面板改为 terminal 内 overlay；命令来自运行时 Pwndbg registry，中文仅为展示翻译层。
- 新增 `/frame /frames /ret /rbp /stackof /safe`。Frame Inspector 以 GDB unwinder 为真值，不再固定假设 `[rbp+8]`。
- 右栏改为仅用户命令的 Operation History；双击只回填，不伪装进程回退。
- 删除默认 live diff；Runtime calibration 保留但折叠。Tutor 不显示 Before/After，不产生攻击假设。
- 修复 Windows drive path 在非 Windows host 被 `Path.resolve()` 破坏的跨宿主回归，并保留 `$ORIGIN`。
- 新增真实 PTY/Pwndbg/frame-pointer/frameless/official-command/fail-open 探针与 1600×1000 UI audit。
- 修复 AArch64/ARM 等跨架构 ELF 被 x86-64 native GDB 自动 `starti` 触发 `i387_supply_xsave` assertion 的崩溃：直接读取 ELF `e_machine`，仅 x86_64/i386 自动执行，异构 ELF 进入可用的静态 Pwndbg 会话。同时用 `-nx` 隔离用户 `.gdbinit`，用 early-init 关闭 debuginfod。
