"""elf-seccomp-patcher（gubaiovo/elf-seccomp-patcher，third_party 内置）的包装模块。

社区 AWD 通防工具：用 LIEF 新增一个只读可执行 PT_LOAD（guard），在原入口前
安装 Landlock 白名单（默认禁 /flag）+ seccomp-BPF（禁 execve/connect/ptrace、
内核模块、mount、BPF、io_uring 等），并设 NO_NEW_PRIVS / PR_SET_DUMPABLE=0、
清空 capabilities。只支持 ELF64 小端 x86-64（PIE / No-PIE），目标运行环境需
Linux 5.13+ 且内核启用 Landlock。依赖 WSL 内 python3 + LIEF + gcc + objcopy。

WSL argv 形状固定在本模块：渲染层只能传预设 id、路径选项与白名单 flag 文本。
"""
from __future__ import annotations

import os
import shlex
import shutil
import time
from datetime import datetime
from pathlib import Path

from .common import diff_runs, resolve_output

PATCHER_ID = "elfseccomp"
ENV_OVERRIDE = "PWNCRAFT_ELF_SECCOMP_DIR"

_DEFAULT_OUTPUT_SUFFIX = ".protected"

# 预设 = 推荐的 flag 组合；显式传入的 flags 逐键覆盖预设。
_PRESETS: dict[str, dict] = {
    "default": {
        "name": "默认策略 · 禁 /flag + 危险 syscall",
        "description": "Landlock 只读放行 /lib /lib64 /usr /etc /dev 与输入目录、"
                       "读写放行 /tmp；seccomp 禁 execve/connect/ptrace 等；允许 clone（兼容 pthread）。",
        "flags": {},
    },
    "strict": {
        "name": "强化 · 追加单线程 + 禁 open",
        "description": "在默认策略上追加 --single-threaded（禁 clone/clone3）与 "
                       "--deny-open（禁 open/creat/openat/openat2）；仅适合单线程且不再打开文件的服务。",
        "flags": {"single_threaded": True, "deny_open": True},
    },
    "networked": {
        "name": "外连放行 · 服务需要上游连接",
        "description": "在默认策略上追加 --allow-connect：放开 connect(2)，"
                       "socket/bind/listen/accept 本来就允许。",
        "flags": {"allow_connect": True},
    },
    "custom": {
        "name": "自定义 · 手动组合 flag",
        "description": "以默认策略为底，按下方 flag 字段自由组合。",
        "flags": {},
    },
}

_FLAG_FIELDS = {
    "single_threaded": "--single-threaded",
    "deny_open": "--deny-open",
    "allow_connect": "--allow-connect",
    "no_default_paths": "--no-default-paths",
}
_EXTRA_FLAG_ALIASES = {
    "--single-threaded": "single_threaded", "--deny-open": "deny_open",
    "--allow-connect": "allow_connect", "--no-default-paths": "no_default_paths",
}


def tool_dir() -> Path:
    """定位 third_party/elf-seccomp-patcher（环境变量可覆盖为权威路径）。"""
    env = os.environ.get(ENV_OVERRIDE, "").strip()
    if env:
        return Path(env)
    package_side = (Path(__file__).resolve().parents[4] / "third_party"
                    / "elf-seccomp-patcher")
    if (package_side / "patcher.py").is_file():
        return package_side
    return Path.cwd() / "third_party" / "elf-seccomp-patcher"


def meta() -> dict:
    return {
        "id": PATCHER_ID,
        "name": "elf-seccomp-patcher（gubaiovo）",
        "description": "LIEF 新增 RX guard 段：入口前装 Landlock 白名单（默认禁 /flag）+ "
                       "seccomp-BPF（禁 execve/connect/ptrace 等），不改 .eh_frame、保留 C++ "
                       "异常与 notes；仅 amd64 ELF64，运行环境需 Linux 5.13+ 且启用 Landlock。"
                       "依赖 WSL 内 python3 + LIEF + gcc + objcopy。",
        "presets": [
            {"id": pid, "name": conf["name"], "description": conf["description"]}
            for pid, conf in _PRESETS.items()
        ],
        "output_suffix": _DEFAULT_OUTPUT_SUFFIX,
        "architectures": "amd64（ELF64 小端，PIE / No-PIE）",
    }


def env_report(runner) -> dict:
    """依赖体检：脚本就位 + WSL LIEF / gcc / objcopy。"""
    script = tool_dir() / "patcher.py"
    checks: list[dict] = [{
        "name": "elf-seccomp-patcher 脚本（third_party）",
        "present": script.is_file(),
        "detail": str(script),
    }]
    lief = runner.run_wsl_argv(["python3", "-c", "import lief; print(lief.__version__)"],
                               timeout=60)
    checks.append({
        "name": "WSL python3 + LIEF",
        "present": lief.ok,
        "detail": lief.stdout.strip() or lief.stderr.strip()[:200],
    })
    for tool in ("gcc", "objcopy"):
        which = runner.run_wsl_argv(["which", tool], timeout=30)
        checks.append({
            "name": f"WSL {tool}",
            "present": which.ok and which.stdout.strip(),
            "detail": which.stdout.strip() or "未找到（apt-get install gcc binutils）",
        })
    return {"checks": checks, "ready": all(item["present"] for item in checks)}


def _split_paths(raw: str, label: str) -> list[str]:
    """逗号/空白分隔的绝对 Linux 路径（Landlock 语义，/mnt/… 也可）。"""
    parts = [p.strip().rstrip("/") for p in str(raw or "").replace("，", ",").split(",")]
    parts = [p for chunk in parts for p in chunk.split() if p.strip()]
    for part in parts:
        if not part.startswith("/"):
            raise ValueError(f"{label} 必须是 WSL 内的绝对路径（以 / 开头），收到: {part!r}")
    seen: list[str] = []
    for part in parts:
        if part not in seen:
            seen.append(part)
    return seen


def _effective_flags(options: dict) -> dict[str, bool]:
    preset = str(options.get("preset") or "default").strip()
    if preset not in _PRESETS:
        raise ValueError("未知 elf-seccomp-patcher 预设，请刷新一键通防页")
    flags = dict(_PRESETS[preset]["flags"])
    for key in _FLAG_FIELDS:
        if key in options and options.get(key) is not None:
            flags[key] = bool(options.get(key))
    extra = str(options.get("extra_flags") or "").strip()
    if extra:
        for token in shlex.split(extra):
            key = _EXTRA_FLAG_ALIASES.get(token)
            if key is None:
                raise ValueError(
                    f"不支持的 flag: {token!r}（只允许 "
                    f"{' / '.join(_EXTRA_FLAG_ALIASES)}）")
            flags[key] = True
    return flags


def run(binary: Path, options: dict, runner, *, timeout: int = 180) -> dict:
    """运行 elf-seccomp-patcher：scratch 隔离 → 产物 diff → 输出落盘。"""
    script = tool_dir() / "patcher.py"
    if not script.is_file():
        raise ValueError(
            f"未找到 elf-seccomp-patcher（期望 {script}）；"
            "仓库需包含 third_party/elf-seccomp-patcher")
    binary = Path(binary)
    if not binary.is_file():
        raise ValueError(f"目标不存在: {binary}")
    work = binary.parent / ".pwncraft" / "work" / "patchers" / PATCHER_ID
    work.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    scratch_elf = work / f"{binary.name}.run_{stamp}"
    shutil.copy2(binary, scratch_elf)
    scratch_out = work / f"{scratch_elf.name}{_DEFAULT_OUTPUT_SUFFIX}"

    flags = _effective_flags(options)
    # wsl --exec 不做任何路径翻译：argv 里的路径分量必须先转成 /mnt/ 形式。
    argv = ["python3", runner.to_wsl_path(script), runner.to_wsl_path(scratch_elf),
            "-o", runner.to_wsl_path(scratch_out)]
    for path in _split_paths(str(options.get("protected_path") or ""), "保护路径"):
        argv += ["--protected-path", path]
    for label, flag in (("allow_ro", "--allow-ro"), ("allow_rw", "--allow-rw")):
        for path in _split_paths(str(options.get(label) or ""), label):
            argv += [flag, path]
    for key, token in _FLAG_FIELDS.items():
        if flags.get(key):
            argv.append(token)

    started = time.monotonic()
    result = runner.run_wsl_argv(argv, timeout=max(30, min(600, int(timeout))))
    elapsed = round((time.monotonic() - started) * 1000)

    if not scratch_out.is_file():
        raise ValueError(_friendly_error(result, elapsed))
    original_bytes = scratch_elf.read_bytes()
    patched_bytes = scratch_out.read_bytes()
    diff = diff_runs(original_bytes, patched_bytes)
    output_path = resolve_output(
        scratch_out, binary, str(options.get("output_dir") or ""),
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
        "scratch_path": str(scratch_out),
        "source_size": len(original_bytes),
        "output_size": len(patched_bytes),
        "diff": diff["runs"],
        "diff_truncated": diff["truncated"],
        "changed_bytes": diff["changed"],
        "same_size": diff["same_size"],
        "flags": {key: bool(flags.get(key)) for key in _FLAG_FIELDS},
        "elapsed_ms": elapsed,
    }


def _friendly_error(result, elapsed: int) -> str:
    """常见环境失败 → 可执行的提示（其余原样透传输出）。"""
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    head = result.combined_output()[:800] or f"退出码 {result.returncode}"
    if "ModuleNotFoundError" in text or "No module named" in text:
        return (f"elf-seccomp-patcher 运行失败（{elapsed} ms）：WSL 的 python3 缺 LIEF，"
                "在 WSL 里执行 python3 -m pip install --user --break-system-packages "
                "lief 后重试。\n" + head)
    if "gcc" in text and ("not found" in text.lower() or "No such file" in text):
        return (f"elf-seccomp-patcher 运行失败（{elapsed} ms）：WSL 缺 gcc/objcopy，"
                "在 WSL 里执行 sudo apt-get install gcc binutils 后重试。\n" + head)
    if result.returncode != 0:
        return (f"elf-seccomp-patcher 运行失败（{elapsed} ms，退出码 "
                f"{result.returncode}）：\n{head}")
    return f"elf-seccomp-patcher 未产出补丁文件（{elapsed} ms）：\n{head}"
