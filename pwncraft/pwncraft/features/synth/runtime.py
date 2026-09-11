"""运行时验证：headless gdb 测偏移 + 执行生成的 EXP（本地、离线、可选）。

两件事都要求用户显式触发（桥 RPC / UI 按钮 / CLI 参数），因为这里会**真的
运行目标二进制**。结果全部带证据（gdb 寄存器/栈转储、EXP stdout 片段），
没有证据就记 NOT_RUN/UNCONFIRMED，不把"没崩"当成"可利用"。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence

from pwncraft.core.cyclic import cyclic_find, cyclic_pattern

DEFAULT_PATTERN_SIZE = 512
_MARKER_DEFAULT = "PWN_SYNTH_OK"

_REG_RE = re.compile(r"^([a-z][a-z0-9]*)\s+(0x[0-9a-fA-F]+)\s", re.MULTILINE)
_STACK_RE = re.compile(r"^(0x[0-9a-fA-F]+):\s*((?:0x[0-9a-fA-F]+(?:\s+|$))+)", re.MULTILINE)
_SIGNAL_RE = re.compile(r"Program received signal (\w+)")
_EXITED_RE = re.compile(r"\[Inferior \d+ .*exited (?:normally|with code (\d+))")


def _pattern_offset(value: int, *, pattern_size: int, n: int | None = None) -> int | None:
    """寄存器/栈字是否落在 cyclic 模式里；是则返回偏移（未知返回 None，不抛）。"""
    for subsequence in ([n] if n is not None else [4, 8]):
        try:
            return int(cyclic_find(value, n=subsequence, length=pattern_size))
        except Exception:
            continue
    return None


def _parse_registers(text: str) -> dict[str, int]:
    return {name: int(value, 16) for name, value in _REG_RE.findall(text or "")}


def _parse_stack(text: str, word_size: int) -> list[tuple[int, int]]:
    words: list[tuple[int, int]] = []
    for match in _STACK_RE.finditer(text or ""):
        base = int(match.group(1), 16)
        for index, chunk in enumerate(match.group(2).split()):
            try:
                value = int(chunk, 16)
            except ValueError:
                continue
            words.append((base + index * word_size, value))
    return words


def _runtime_argv(binary: Path) -> list[str] | None:
    """附件运行时拉起：同目录有 ld-linux 时用 `<ld> <binary>` 方式运行。

    SomeBox2.0 类真题依赖自带 libc，系统加载器版本不匹配直接报错；这是
    `synth_verify` 对此类题 gdb 报错的根因。返回 None 表示用默认方式。
    """
    binary = Path(binary)
    loaders = [item for item in binary.parent.iterdir()
               if item.is_file() and re.match(r"ld-linux[^/]*\.so", item.name)]
    return [str(loaders[0]), str(binary)] if loaders else None


def _gdb_args(binary_wsl: str, pattern_wsl: str, bits: int,
              argv: list[str] | None = None) -> list[str]:
    word = "g" if bits == 64 else "w"
    args = [
        "-q", "-batch", "-nx",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-ex", "set width 0",
        "-ex", f"run < '{pattern_wsl}'",
        "-ex", "info registers",
        "-ex", f"x/64{word}x $rsp",
    ]
    if argv:
        args += ["--args", *[str(item) for item in argv]]
    else:
        args += ["--args", binary_wsl]
    return args


def resolve_offset(registers: dict[str, int], stack: Sequence[tuple[int, int]], *,
                   bits: int, pattern_size: int = DEFAULT_PATTERN_SIZE) -> dict:
    """从寄存器/栈转储推导保存返回地址偏移（纯函数，可离线单测）。

    优先级：saved_rip（返回地址已被 ret 使用）＞ saved_rbp（帧指针被覆盖，
    偏移=命中值+字长）＞ stack_scan（栈上首个模式字到 rbp+字长，置信度 partial）。
    """
    word_size = 8 if int(bits) == 64 else 4
    evidence: list[str] = []
    notes: list[str] = []
    ip = registers.get("rip", registers.get("eip"))
    bp = registers.get("rbp", registers.get("ebp"))
    sp = registers.get("rsp", registers.get("esp"))
    for name, value in (("rip", ip), ("rbp", bp), ("rsp", sp)):
        if value is not None:
            evidence.append(f"gdb: {name}=0x{value:x}")

    offset: int | None = None
    method = "none"
    confidence = "none"
    if ip is not None:
        hit = _pattern_offset(ip, pattern_size=pattern_size)
        if hit is not None:
            offset, method, confidence = hit, "saved_rip", "proven"
    if offset is None and bp is not None:
        hit = _pattern_offset(bp, pattern_size=pattern_size)
        if hit is not None:
            offset, method, confidence = hit + word_size, "saved_rbp", "proven"
    if offset is None and bp is not None and stack:
        saved_ip_slot = bp + word_size
        for address, value in stack:
            hit = _pattern_offset(value, pattern_size=pattern_size)
            if hit is None:
                continue
            # 该字位于 输入缓冲区起点 + hit 处；保存返回地址槽相对它的距离要补回 hit。
            distance = saved_ip_slot - address
            if distance > 0:
                offset, method, confidence = distance + hit, "stack_scan", "partial"
                evidence.append(
                    f"栈扫描: 0x{address:x} 命中模式(偏移 0x{hit:x})，"
                    f"保存返回地址槽 0x{saved_ip_slot:x}")
            break
    if offset is not None:
        evidence.append(f"cyclic: offset = 0x{offset:x}（方法 {method}）")
    else:
        notes.append("没有寄存器/栈字命中 cyclic 模式：无法证明保存返回地址偏移")
    return {"offset": offset, "method": method, "confidence": confidence,
            "evidence": evidence, "notes": notes, "registers": dict(registers),
            "word_size": word_size, "pattern_size": pattern_size}


def discover_stack_offset(
    binary: str | Path,
    *,
    runner,
    bits: int,
    pattern_size: int = DEFAULT_PATTERN_SIZE,
    timeout: int = 30,
    menu_steps: "list[dict] | None" = None,
) -> dict:
    """headless gdb：喂 cyclic → 解析寄存器/栈 → 推导保存返回地址偏移。

    方法优先级（全部来自真实崩溃现场）：
      saved_rip  —— rip/eip 命中模式（返回地址被覆盖且已 ret 过去）
      saved_rbp  —— rbp/ebp 命中（保存帧指针被覆盖）：偏移 = 命中值 + 字长
      stack_scan —— 栈上第一个模式字到 rbp+字长 的距离（帧破坏更严重时，置信度 partial）
    """
    path = Path(binary)
    with tempfile.TemporaryDirectory(prefix="pwncraft-synth-") as folder:
        pattern_file = Path(folder) / "pattern.bin"
        pattern_file.write_bytes(cyclic_pattern(pattern_size))
        pattern_wsl = str(runner.to_wsl_path(pattern_file))
        if "'" in pattern_wsl or "\n" in pattern_wsl:
            return {"offset": None, "method": "none", "confidence": "none",
                    "evidence": [], "notes": ["临时路径含引号，无法安全传给 gdb"],
                    "registers": {}, "word_size": 8 if int(bits) == 64 else 4}
        binary_wsl = str(runner.to_wsl_path(path))
        argv = _runtime_argv(path)
        if argv is not None:
            argv = [str(runner.to_wsl_path(Path(item))) for item in argv]
        # 菜单题：先送选项再喂 pattern（菜单预驱动），否则 cyclic 打进菜单 scanf
        pattern_data = pattern_file.read_bytes()
        if menu_steps:
            prelude = "".join(str(step.get("send") or "") + "\n"
                              for step in menu_steps)
            pattern_file.write_bytes(prelude.encode() + pattern_data)
        result = runner.run_tool("gdb", _gdb_args(binary_wsl, pattern_wsl, bits, argv),
                                 timeout=timeout)

    stdout = result.stdout or ""
    stderr = result.stderr or ""
    word_size = 8 if int(bits) == 64 else 4
    resolved = resolve_offset(_parse_registers(stdout), _parse_stack(stdout, word_size),
                              bits=bits, pattern_size=pattern_size)
    notes = list(resolved["notes"])
    signal = _SIGNAL_RE.search(stdout)
    if signal:
        resolved["evidence"].insert(0, f"gdb: Program received signal {signal.group(1)}")
    elif _EXITED_RE.search(stdout):
        notes.append("程序正常退出（没有触发崩溃）：可能不经过该输入路径或长度不足")
    if not result.ok and not stdout:
        notes.append(f"gdb 执行失败：{(stderr or '').strip()[:200] or result.returncode}")
    resolved["notes"] = notes
    resolved["stdout_tail"] = "\n".join(stdout.strip().splitlines()[-12:])
    return resolved


_PTR_ECHO = re.compile(rb"0x[0-9a-f]{6,12}")


def probe_fmt_control(binary, *, runner, timeout: int = 12) -> dict:
    """fmt 探针实验：真跑目标送 %9$08x.%9$08x 样式输入，看回显是否含
    受控十六进制（同一值出现两次 = 格式串受输入控制，intelpwn 同款判据）。

    返回 {'controlled': bool, 'offset': int|None, 'evidence': [...]}；
    识别不出（无回显/超时/不匹配）时 controlled=False 并给出原因。
    """
    from pwncraft.core.wsl import prepare_windows_system_process

    probes = [b"%p.%p.%p.%p", b"AAAA%08x.%08x"]
    for probe in probes:
        try:
            prepare_windows_system_process()
            argv = _runtime_argv(Path(binary)) or [str(binary)]
            argv = [str(runner.to_wsl_path(Path(item))) for item in argv]
            proc = subprocess.run(
                ["wsl.exe", "--exec", *argv],
                input=probe + b"\n", capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            continue
        out = proc.stdout or b""
        marker = probe.split(b".")[0]
        # 受控判据：回显里能找到输入字面量之外的 0x 指针形态，且数量 >= 2
        hits = _PTR_ECHO.findall(out)
        if len(hits) >= 2 and marker not in out:
            return {"controlled": True, "probe": probe.decode(),
                    "evidence": [f"echo: {out[:120]!r}", f"命中 {len(hits)} 个指针形态"],
                    "offset": None}
        if probe == probes[-1]:
            return {"controlled": False,
                    "evidence": [f"echo: {out[:120]!r}"],
                    "reason": "回显未见受控十六进制（格式串可能不可控或无回显）"}
    return {"controlled": False, "evidence": [], "reason": "探针未能运行目标"}


def _executor(script: Path, runner) -> list[str]:
    """优先本机跑（WSL/Linux 宿主）；Windows 宿主经 wsl.exe 跑同一脚本。"""
    if os.name == "posix":
        return [sys.executable, str(script)]
    translated = runner.to_wsl_path(script) if runner is not None else str(script)
    return ["wsl.exe", "--", "python3", str(translated)]


def run_exp_source(
    source: str,
    *,
    runner=None,
    target_path: str | Path | None = None,
    marker: str = _MARKER_DEFAULT,
    command: str = "",
    timeout: int = 60,
) -> dict:
    """执行生成的 EXP（opt-in）：喂 `echo <marker>; exit` 看是否拿到 shell。

    只改 TARGET 常量行（渲染器固定格式），其余源码原样执行——验证的是产物本身。
    """
    text = str(source or "")
    if target_path is not None:
        if os.name != "posix" and runner is not None:
            target_path = runner.to_wsl_path(target_path)
        replaced = False
        lines: list[str] = []
        for line in text.splitlines():
            if not replaced and line.startswith("TARGET = "):
                lines.append(f"TARGET = {str(target_path)!r}")
                replaced = True
            else:
                lines.append(line)
        text = "\n".join(lines) + "\n"
    feed = (command or f"echo {marker}; exit") + "\n"
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pwncraft-synth-run-") as folder:
        script = Path(folder) / "generated_exp.py"
        script.write_text(text, encoding="utf-8")
        try:
            proc = subprocess.run(_executor(script, runner), input=feed.encode(),
                                  capture_output=True, timeout=timeout)
            returncode, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
            error = ""
        except subprocess.TimeoutExpired as error_info:
            returncode = -1
            stdout = (error_info.stdout or b"") if isinstance(error_info.stdout, bytes) else b""
            stderr = (error_info.stderr or b"") if isinstance(error_info.stderr, bytes) else b""
            error = f"EXP 执行超时（{timeout}s）"
        except OSError as error_info:
            returncode, stdout, stderr, error = -1, b"", b"", str(error_info)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    out_text = stdout.decode("utf-8", "replace")
    err_text = stderr.decode("utf-8", "replace")
    return {
        "verified": marker in (out_text + err_text),
        "marker": marker, "returncode": returncode, "elapsed_ms": elapsed_ms,
        "error": error,
        "stdout_tail": "\n".join(out_text.strip().splitlines()[-6:]),
        "stderr_tail": "\n".join(err_text.strip().splitlines()[-4:]),
    }


def summarize_runtime(runtime: dict, execution: dict | None) -> dict:
    """把运行时发现与 EXP 执行结果压成一句结论 + 证据列表（供 RPC/UI 展示）。"""
    evidence: list[str] = list(runtime.get("evidence") or [])
    if execution is None:
        return {"status": "NOT_RUN", "summary": "未执行 EXP（缺少可用策略或偏移）",
                "evidence": evidence}
    if execution.get("verified"):
        return {"status": "VERIFIED_SHELL", "summary": "生成的 EXP 打通目标（marker 命中）",
                "evidence": evidence + [f"EXP stdout: {execution.get('stdout_tail')}"]}
    if execution.get("error"):
        return {"status": "UNCONFIRMED", "summary": execution["error"], "evidence": evidence}
    return {"status": "UNCONFIRMED",
            "summary": f"EXP 已运行但未命中 marker（返回码 {execution.get('returncode')}）",
            "evidence": evidence + [f"EXP stderr: {execution.get('stderr_tail')}"]}
