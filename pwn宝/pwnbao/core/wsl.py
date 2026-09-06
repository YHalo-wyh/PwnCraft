from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import datetime as _dt
import os
import re
import shutil
import subprocess

from pwnbao.core.external_process import hidden_windows_process_kwargs, prepare_windows_system_process


ALLOWED_TOOLS = {
    "file",
    "checksec",
    "readelf",
    "objdump",
    "patchelf",
    # Read-only query tools added for the Workbench Truth Engine.  None of
    # these mutate the target binary, unlike patchelf above.
    "nm",
    "strings",
    "ldd",
    "ropgadget",
    "ropper",
    "one_gadget",
    "seccomp-tools",
}
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def decode_wsl_output(data: bytes | str) -> str:
    """Decode Linux UTF-8 and Windows UTF-16 diagnostics, including mixed lines."""
    if isinstance(data, str):
        return data
    parts: list[str] = []
    while data:
        sample = data[:32]
        odd = sample[1::2]
        even = sample[::2]
        encoding = None
        if data.startswith(b"\xff\xfe") or (odd and odd.count(0) / len(odd) > 0.4):
            encoding = "utf-16-le"
        elif data.startswith(b"\xfe\xff") or (even and even.count(0) / len(even) > 0.4):
            encoding = "utf-16-be"
        if encoding:
            newline = "\n".encode(encoding)
            end = next((i + 2 for i in range(0, len(data) - 1, 2)
                        if data[i:i + 2] == newline), len(data))
        else:
            encoding = "utf-8-sig"
            index = data.find(b"\n")
            end = index + 1 if index >= 0 else len(data)
        parts.append(data[:end].decode(encoding, errors="replace").lstrip("\ufeff"))
        data = data[end:]
    return "".join(parts)


@dataclass(frozen=True)
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def combined_output(self) -> str:
        return "\n".join(part for part in [self.stdout.strip(), self.stderr.strip()] if part)


class WslToolRunner:
    def __init__(self, wsl_exe: str = "wsl.exe"):
        self.wsl_exe = wsl_exe

    def to_wsl_path(self, path: str | Path) -> str:
        raw = os.fspath(path)
        # Dynamic-loader tokens are arguments, not host filesystem paths.
        if raw.startswith("$"):
            return raw.replace("\\", "/")
        if _WINDOWS_ABSOLUTE_RE.match(raw):
            win = PureWindowsPath(raw)
            drive = win.drive.rstrip(":").lower()
            parts = [part for part in win.parts[1:]]
            return "/mnt/" + drive + "/" + "/".join(parts)
        # Already-WSL and native Linux absolute paths must remain native.  In
        # particular, never feed ``C:\\...`` through host Path.resolve() on a
        # Linux CI host before this boundary has classified it.
        if raw.startswith("/"):
            return raw.replace("\\", "/")
        resolved = Path(raw).resolve()
        win = PureWindowsPath(str(resolved))
        drive = win.drive.rstrip(":").lower()
        if not drive:
            return str(resolved).replace("\\", "/")
        parts = [part for part in win.parts[1:]]
        return "/mnt/" + drive + "/" + "/".join(parts)

    def run_tool(self, tool: str, args: list[str], timeout: int = 30) -> ToolResult:
        if tool not in ALLOWED_TOOLS:
            raise ValueError(f"不允许调用工具: {tool}")
        # ``wsl.exe command args`` is parsed through WSL's legacy command-line
        # compatibility layer and drops/expands values such as ``$ORIGIN``.
        # ``--exec`` preserves argv exactly, which is mandatory for patchelf.
        prepare_windows_system_process()
        command = [self.wsl_exe, "--exec", tool, *args]
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            **hidden_windows_process_kwargs(),
        )
        return ToolResult(command, proc.returncode,
                          decode_wsl_output(proc.stdout), decode_wsl_output(proc.stderr))

    def file(self, path: str | Path) -> ToolResult:
        return self.run_tool("file", [self.to_wsl_path(path)])

    def checksec(self, path: str | Path) -> ToolResult:
        return self.run_tool("checksec", ["--file=" + self.to_wsl_path(path)])

    def readelf_header(self, path: str | Path) -> ToolResult:
        return self.run_tool("readelf", ["-h", self.to_wsl_path(path)])

    def patchelf(
        self,
        binary_path: str | Path,
        interpreter_path: str | Path | None,
        rpath_dir: str | Path | None,
        libc_path: str | Path | None = None,
    ) -> tuple[Path, ToolResult]:
        binary = Path(binary_path)
        timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup = binary.with_name(binary.name + f".bak.{timestamp}")
        shutil.copy2(binary, backup)

        args: list[str] = []
        if interpreter_path:
            args.extend(["--set-interpreter", self.to_wsl_path(interpreter_path)])
        if rpath_dir:
            args.extend(["--set-rpath", self.to_wsl_path(rpath_dir)])
        if libc_path:
            libc_name = Path(libc_path).name
            if libc_name != "libc.so.6":
                args.extend(["--replace-needed", "libc.so.6", libc_name])
        args.append(self.to_wsl_path(binary))
        return backup, self.run_tool("patchelf", args, timeout=30)

    def patchelf_interpreter(self, binary_path: str | Path) -> ToolResult:
        return self.run_tool("patchelf", ["--print-interpreter", self.to_wsl_path(binary_path)])

    def patchelf_rpath(self, binary_path: str | Path) -> ToolResult:
        return self.run_tool("patchelf", ["--print-rpath", self.to_wsl_path(binary_path)])

    def patchelf_needed(self, binary_path: str | Path) -> ToolResult:
        return self.run_tool("patchelf", ["--print-needed", self.to_wsl_path(binary_path)])
