"""evilPatcher（TTY-flag/evilPatcher，third_party/evilPatcher 内置）的包装模块。

社区 AWD pwn 通防工具：用 seccomp-tools 把沙箱规则编译成 BPF，改写 _start
传给 __libc_start_main 的 main 指针，把 prctl(NO_NEW_PRIVS)+SECCOMP 安装
shellcode 注入 .eh_frame，并把对应 PT_LOAD 段提为可执行；改动 < 0x100 字节、
不改文件头，自动识别 i386/amd64 与 PIE。

WSL argv 形状固定在本模块：渲染层只能传预设 id、规则文本与输出目录/文件名。
"""
from __future__ import annotations

import os
import shutil
import time
from datetime import datetime
from pathlib import Path

from .common import diff_runs, resolve_output

PATCHER_ID = "evilpatcher"
ENV_OVERRIDE = "PWNCRAFT_EVILPATCHER_DIR"

_PRESET_LABELS = {
    "mini_sandbox": ("mini_sandbox · 仅禁 execve", "最小黑名单：只拦截 execve"),
    "sandbox1": ("sandbox1 · 禁 execve + open", "拦截 execve/open（含 x32 兼容位检查）"),
    "sandbox2": ("sandbox2 · 禁 open 系 + mmap + ptrace",
                 "拦截 open/openat/open_by_handle_at/mmap/ptrace"),
    "sandbox3": ("sandbox3 · 禁 socket 系 + clone + execve",
                 "拦截 socket/connect/bind/listen/clone/execve"),
}

_DEFAULT_OUTPUT_SUFFIX = ".patch"


def tool_dir() -> Path:
    """定位 third_party/evilPatcher。

    PWNCRAFT_EVILPATCHER_DIR 一旦设置即为权威（缺失时报错，便于发现问题）；
    否则优先包相对的 third_party/，再退 cwd 相对（供报错信息引用）。
    """
    env = os.environ.get(ENV_OVERRIDE, "").strip()
    if env:
        return Path(env)
    package_side = Path(__file__).resolve().parents[4] / "third_party" / "evilPatcher"
    if (package_side / "evilPatcher.py").is_file():
        return package_side
    return Path.cwd() / "third_party" / "evilPatcher"


def _sandbox_presets() -> list[dict]:
    """枚举工具自带的 sandboxs/*.asm 预设（id/名称/说明/规则原文）。"""
    out: list[dict] = []
    sandbox_dir = tool_dir() / "sandboxs"
    if not sandbox_dir.is_dir():
        return out
    for path in sorted(sandbox_dir.glob("*.asm")):
        try:
            code = path.read_text(encoding="utf-8")
        except OSError:
            continue
        label, description = _PRESET_LABELS.get(path.stem, (path.stem, ""))
        out.append({"id": path.stem, "name": label, "description": description,
                    "code": code.strip() + "\n"})
    return out


def meta() -> dict:
    presets = [dict(item, code=None) for item in _sandbox_presets()]
    presets.append({"id": "custom", "name": "自定义 seccomp-tools 规则…",
                    "description": "按 seccomp-tools asm 语法填写规则文本"})
    return {
        "id": PATCHER_ID,
        "name": "evilPatcher（TTY-flag）",
        "description": "seccomp 沙箱 BPF 注入：改写 _start 的 main 指针，安装 shellcode "
                       "放 .eh_frame 并提权 PT_LOAD；< 0x100 字节改动、文件大小不变，"
                       "支持 i386/amd64 与 PIE。依赖 WSL 内 python3 + pwntools + seccomp-tools。",
        "presets": presets,
        "output_suffix": _DEFAULT_OUTPUT_SUFFIX,
        "architectures": "i386 / amd64（PIE 均可）",
    }


def env_report(runner) -> dict:
    """evilPatcher 依赖体检：脚本就位 + WSL python3/pwntools + seccomp-tools。"""
    script = tool_dir() / "evilPatcher.py"
    checks: list[dict] = [{
        "name": "evilPatcher 脚本（third_party）",
        "present": script.is_file(),
        "detail": str(script),
    }]
    pwn = runner.run_wsl_argv(
        ["python3", "-c", "import pwnlib; print(pwnlib.__version__)"], timeout=60)
    checks.append({
        "name": "WSL python3 + pwntools",
        "present": pwn.ok,
        "detail": pwn.stdout.strip() or pwn.stderr.strip()[:200],
    })
    tools = runner.run_wsl_argv(["seccomp-tools", "--version"], timeout=30)
    checks.append({
        "name": "WSL seccomp-tools",
        "present": tools.ok,
        "detail": tools.stdout.strip() or tools.stderr.strip()[:200],
    })
    return {"checks": checks, "ready": all(item["present"] for item in checks)}


def _resolve_sandbox(options: dict) -> str:
    preset = str(options.get("preset") or "").strip()
    policy = str(options.get("policy") or "").strip()
    if preset == "custom" or (not preset and policy):
        if not policy:
            raise ValueError("自定义规则为空：请按 seccomp-tools asm 语法填写，"
                             "例如 `A == execve ? dead : next` + `return KILL`")
        return policy
    presets = {item["id"]: item for item in _sandbox_presets()}
    if preset not in presets:
        raise ValueError("未知沙箱预设，请重新打开一键通防页刷新预设列表")
    return presets[preset]["code"]


def run(binary: Path, options: dict, runner, *, timeout: int = 180) -> dict:
    """对工作副本运行 evilPatcher：scratch 隔离 → 产物 diff → 输出落盘。

    工具约定输入 ELF 只读、输出写到 `<输入路径>.patch`；因此把当前工作副本
    拷进 `.pwncraft/work/patchers/evilpatcher/` 的带时间戳 scratch 再执行，
    绝不污染原题目目录，也不直接改工作副本（采纳需显式走 patcher_adopt）。
    """
    script = tool_dir() / "evilPatcher.py"
    if not script.is_file():
        raise ValueError(
            f"未找到 evilPatcher（期望 {script}）；仓库需包含 third_party/evilPatcher")
    sandbox_code = _resolve_sandbox(options)
    binary = Path(binary)
    if not binary.is_file():
        raise ValueError(f"目标不存在: {binary}")
    work = binary.parent / ".pwncraft" / "work" / "patchers" / PATCHER_ID
    work.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    scratch_elf = work / f"{binary.name}.run_{stamp}"
    shutil.copy2(binary, scratch_elf)
    sandbox_file = work / f"sandbox_{stamp}.asm"
    sandbox_file.write_text(sandbox_code + "\n", encoding="utf-8")

    # wsl --exec 不做任何路径翻译：argv 里的路径分量必须先转成 /mnt/ 形式，
    # 否则 python3 会把 `F:\...` 当作相对文件名（cwd 前缀拼接后直接 ENOENT）。
    verbose = bool(options.get("verbose", True))
    argv = ["python3", runner.to_wsl_path(script), runner.to_wsl_path(scratch_elf),
            runner.to_wsl_path(sandbox_file)]
    if verbose:
        argv.append("1")
    started = time.monotonic()
    result = runner.run_wsl_argv(argv, timeout=max(30, min(600, int(timeout))))
    elapsed = round((time.monotonic() - started) * 1000)

    product = Path(str(scratch_elf) + ".patch")
    if not product.is_file():
        raise ValueError(_friendly_error(result, elapsed))
    original_bytes = scratch_elf.read_bytes()
    patched_bytes = product.read_bytes()
    diff = diff_runs(original_bytes, patched_bytes)
    output_path = resolve_output(
        product, binary, str(options.get("output_dir") or ""),
        str(options.get("output_name") or ""), binary.name + _DEFAULT_OUTPUT_SUFFIX,
        protected=tuple(Path(p) for p in options.get("_protected") or ()))
    return {
        "ok": True,
        "patcher": PATCHER_ID,
        "returncode": result.returncode,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-4000:],
        "source": str(binary),
        "output_path": str(output_path),
        "scratch_path": str(product),
        "source_size": len(original_bytes),
        "output_size": len(patched_bytes),
        "diff": diff["runs"],
        "diff_truncated": diff["truncated"],
        "changed_bytes": diff["changed"],
        "same_size": diff["same_size"],
        "sandbox": sandbox_code,
        "elapsed_ms": elapsed,
    }


def _friendly_error(result, elapsed: int) -> str:
    """工具常见环境失败 → 可执行的提示（其余原样透传输出）。"""
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    head = result.combined_output()[:800] or f"退出码 {result.returncode}"
    if "No module named" in text or "ModuleNotFoundError" in text:
        return (f"evilPatcher 运行失败（{elapsed} ms）：WSL 的 python3 缺 pwntools，"
                f"在 WSL 里执行 pip install pwntools 后重试。\n{head}")
    if "Seccomp-tools required" in text or "seccomp-tools: not found" in text:
        return (f"evilPatcher 运行失败（{elapsed} ms）：WSL 缺 seccomp-tools，"
                f"在 WSL 里执行 gem install seccomp-tools 后重试。\n{head}")
    if "is not supported" in text:
        return f"evilPatcher 仅支持 i386 / amd64 ELF：\n{head}"
    if result.returncode != 0:
        return f"evilPatcher 运行失败（{elapsed} ms，退出码 {result.returncode}）：\n{head}"
    return f"evilPatcher 未产出补丁文件（{elapsed} ms）：\n{head}"
