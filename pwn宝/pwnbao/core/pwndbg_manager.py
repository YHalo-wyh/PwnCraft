from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import hashlib
import os
import shlex
import subprocess
import urllib.request

from pwnbao.core.external_process import hidden_windows_process_kwargs, prepare_windows_system_process
from pwnbao.core.wsl import WslToolRunner


PWNDBG_VERSION = "2026.07.29"
PWNDBG_MOGAI_VERSION = "2026.07.29-pwndbg-mogai.16"
PWNDBG_MOGAI_COMMAND = "pwndbg-mogai"
PWNDBG_RELEASE_URL = f"https://github.com/pwndbg/pwndbg/releases/tag/{PWNDBG_VERSION}"
PWNDBG_ASSETS = {
    "x86_64": {
        "name": f"pwndbg_{PWNDBG_VERSION}_x86_64-portable.tar.xz",
        "sha256": "63c38b76bf8baeb44b4bc018c73ea0b05b872c2aba205ed5680892f2d65adb03",
        "size": 107_920_228,
    },
}


@dataclass(frozen=True)
class PwndbgLaunchSpec:
    program: str
    arguments: tuple[str, ...]
    elf_wsl_path: str
    version: str = PWNDBG_VERSION
    pty_command: tuple[str, ...] = ()
    extension_wsl_path: str = ""
    target_architecture: str = "unknown"
    auto_start: bool = False


class PwndbgManager:
    """Install an isolated ``pwndbg-mogai`` beside, never over, user Pwndbg."""

    def __init__(self, wsl_exe: str = "wsl.exe", download_root: str | Path | None = None):
        self.wsl_exe = wsl_exe
        self.runner = WslToolRunner(wsl_exe)
        local = os.environ.get("LOCALAPPDATA")
        default_root = Path(local) / "pwnbao" / "downloads" if local else Path.home() / ".pwnbao" / "downloads"
        self.download_root = Path(download_root) if download_root else default_root
        self.mogai_root = f"$HOME/.local/share/pwnbao/pwndbg-mogai/{PWNDBG_MOGAI_VERSION}"
        self.install_root = f"{self.mogai_root}/runtime"
        self.source_root = f"{self.mogai_root}/source"
        self.command_path = f"$HOME/.local/bin/{PWNDBG_MOGAI_COMMAND}"
        self.config_root = "$HOME/.config/pwnbao/pwndbg-mogai"
        self.cache_root = "$HOME/.cache/pwnbao/pwndbg-mogai"
        self.data_root = "$HOME/.local/share/pwnbao/pwndbg-mogai/data"
        self._legacy_runtime = f"$HOME/.local/share/pwnbao/pwndbg/{PWNDBG_VERSION}"

    def _run_wsl(self, script: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        prepare_windows_system_process()
        return subprocess.run(
            [self.wsl_exe, "--exec", "sh", "-lc", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            **hidden_windows_process_kwargs(),
        )

    def architecture(self) -> str:
        result = self._run_wsl("uname -m", timeout=10)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "无法查询 WSL 架构")
        return result.stdout.strip()

    def is_installed(self) -> bool:
        source_marker = self._source_marker()
        command = (
            f'test -x "{self.install_root}/bin/pwndbg" && '
            f'test -f "{self.source_root}/launcher.sh" && '
            f'test -x "{self.command_path}" && '
            f'test "$(cat "{self.source_root}/PWNDBG_MOGAI_VERSION" 2>/dev/null || true)" '
            f'= "{source_marker}"'
        )
        try:
            return self._run_wsl(command, timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _source_marker() -> str:
        """Identify the exact bundled fork source, not only its runtime version."""
        root = Path(__file__).resolve().parents[2] / "third_party" / "pwndbg-mogai"
        digest = hashlib.sha256()
        if root.is_dir():
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                if path.name.endswith((".pyc", ".pyo")) or "__pycache__" in path.parts:
                    continue
                digest.update(path.relative_to(root).as_posix().encode("utf-8"))
                try:
                    digest.update(path.read_bytes())
                except OSError:
                    continue
        return f"{PWNDBG_MOGAI_VERSION}-{digest.hexdigest()[:16]}"

    def ensure_installed(self, progress: Callable[[str], None] | None = None) -> str:
        emit = progress or (lambda _message: None)
        if self.is_installed():
            emit(f"{PWNDBG_MOGAI_COMMAND} {PWNDBG_MOGAI_VERSION} 已安装；官方 pwndbg 未改动")
            return self.command_path
        arch = self.architecture()
        asset = PWNDBG_ASSETS.get(arch)
        if asset is None:
            raise RuntimeError(f"当前自动安装暂不支持 WSL 架构: {arch}")
        legacy_available = self._run_wsl(
            f'test -x "{self._legacy_runtime}/bin/pwndbg"', timeout=10
        ).returncode == 0
        archive_wsl = "/dev/null"
        if legacy_available:
            emit("发现 Pwn宝旧版私有 runtime，离线复制到 pwndbg-mogai；不读取官方 pwndbg")
        else:
            self.download_root.mkdir(parents=True, exist_ok=True)
            archive = self.download_root / str(asset["name"])
            if not self._verify_archive(archive, str(asset["sha256"])):
                partial = archive.with_suffix(archive.suffix + ".part")
                emit(f"下载 Pwndbg {PWNDBG_VERSION}（约 {int(asset['size']) // 1024 // 1024} MiB）")
                url = f"https://github.com/pwndbg/pwndbg/releases/download/{PWNDBG_VERSION}/{asset['name']}"
                self._download(url, partial, int(asset["size"]), emit)
                if not self._verify_archive(partial, str(asset["sha256"])):
                    raise RuntimeError("Pwndbg 下载完成但 SHA256 不匹配")
                os.replace(partial, archive)
            emit("SHA256 已验证")
            archive_wsl = self.runner.to_wsl_path(archive.resolve())
        emit("正在部署独立 pwndbg-mogai runtime/source/config")
        fork_root = Path(__file__).resolve().parents[2] / "third_party" / "pwndbg-mogai"
        if not fork_root.is_dir():
            raise RuntimeError(f"pwndbg-mogai 源码缺失: {fork_root}")
        fork_root_wsl = self.runner.to_wsl_path(fork_root)
        temporary = f'{self.mogai_root}.installing'
        # Never touch command -v pwndbg, ~/.gdbinit or ~/.config/pwndbg.  The
        # old Pwnbao portable runtime may be copied as an offline migration,
        # but it is not the user's official Pwndbg tree.
        script = (
            "set -eu; "
            f'rm -rf "{temporary}"; mkdir -p "{temporary}/source"; '
            f'if test -x "{self._legacy_runtime}/bin/pwndbg"; then '
            f'  mkdir -p "{temporary}/runtime"; cp -a "{self._legacy_runtime}/." "{temporary}/runtime/"; '
            "else "
            f'  tar -xJf {shlex.quote(archive_wsl)} -C "{temporary}"; '
            f'  mv "{temporary}/pwndbg" "{temporary}/runtime"; '
            "fi; "
            f'(cd {shlex.quote(fork_root_wsl)} && '
            " tar --exclude=.git --exclude=__pycache__ --exclude='*.py[co]' -cf - .) | "
            f'tar -xf - -C "{temporary}/source"; '
            f'printf %s {shlex.quote(self._source_marker())} > "{temporary}/source/PWNDBG_MOGAI_VERSION"; '
            f'test -x "{temporary}/runtime/bin/pwndbg"; test -f "{temporary}/source/launcher.sh"; '
            f'mkdir -p "$(dirname "{self.mogai_root}")" "$(dirname "{self.command_path}")" '
            f'"{self.config_root}" "{self.cache_root}" "{self.data_root}"; '
            f'rm -rf "{self.mogai_root}"; mv "{temporary}" "{self.mogai_root}"; '
            f'cat > "{self.command_path}" <<\'PWNDBG_MOGAI_EOF\'\n'
            "#!/bin/sh\n"
            f'exec sh "$HOME/.local/share/pwnbao/pwndbg-mogai/{PWNDBG_MOGAI_VERSION}/source/launcher.sh" '
            "--quiet -nx \"$@\"\n"
            "PWNDBG_MOGAI_EOF\n"
            f'chmod 755 "{self.command_path}"; '
            f'"{self.command_path}" --version'
        )
        result = self._run_wsl(script, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "pwndbg-mogai 部署失败")
        emit(result.stdout.strip() or f"{PWNDBG_MOGAI_COMMAND} 安装完成；官方 pwndbg 未改动")
        return self.command_path

    def launch_spec(self, elf_path: str | Path) -> PwndbgLaunchSpec:
        elf_wsl = self.runner.to_wsl_path(elf_path)
        target_architecture = self._elf_architecture(elf_path)
        # 用户口径：调试会话停在 pwndbg> 提示符即可，不自动 start——
        # 程序什么时候跑、断在哪，由用户自己决定（starti/断点都行）。
        auto_start = False
        startup = ""
        command = (
            f'PWNBAO_BRIDGE=1 exec "{self.command_path}" -nx '
            "-iex 'set debuginfod enabled off' "
            f'{shlex.quote(elf_wsl)} '
            # GDB's own styled output is part of the fused Pwndbg surface;
            # keep it enabled alongside pwndbg.color's ANSI palette.
            "-ex 'set disable-colors off' -ex 'set style enabled on' -ex 'set architecture auto' "
            "-ex 'set pagination off' -ex 'set confirm off' "
            f'{startup}'
        )
        pty_command = ("sh", "-lc", command)
        return PwndbgLaunchSpec(
            self.wsl_exe,
            pty_command,
            elf_wsl,
            PWNDBG_VERSION,
            pty_command,
            self.source_root,
            target_architecture,
            auto_start,
        )

    @staticmethod
    def _elf_architecture(path: str | Path) -> str:
        try:
            with Path(path).open("rb") as stream:
                header = stream.read(20)
        except OSError:
            return "unknown"
        if len(header) < 20 or header[:4] != b"\x7fELF":
            return "unknown"
        byteorder = "little" if header[5] == 1 else "big" if header[5] == 2 else ""
        if not byteorder:
            return "unknown"
        machine = int.from_bytes(header[18:20], byteorder)
        return {
            0x03: "i386",
            0x08: "mips",
            0x14: "powerpc",
            0x28: "arm",
            0x3E: "x86_64",
            0xB7: "aarch64",
            0xF3: "riscv",
        }.get(machine, f"machine_{machine:#x}")

    @staticmethod
    def _verify_archive(path: Path, expected_sha256: str) -> bool:
        if not path.is_file():
            return False
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError:
            return False
        return digest.hexdigest().lower() == expected_sha256.lower()

    @staticmethod
    def _download(
        url: str,
        destination: Path,
        expected_size: int,
        progress: Callable[[str], None],
    ) -> None:
        request = urllib.request.Request(url, headers={"User-Agent": "pwnbao-pwndbg-installer/1"})
        downloaded = 0
        next_report = 0
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                output.write(block)
                downloaded += len(block)
                percent = int(downloaded * 100 / max(1, expected_size))
                if percent >= next_report:
                    progress(f"下载 Pwndbg：{min(percent, 100)}%")
                    next_report = percent + 5
        if downloaded <= 0:
            raise RuntimeError("Pwndbg 下载为空")
