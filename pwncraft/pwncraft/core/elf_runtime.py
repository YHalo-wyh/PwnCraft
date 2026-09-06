from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil

from pwncraft.core.wsl import ToolResult, WslToolRunner


@dataclass(frozen=True)
class RuntimePair:
    loader: Path
    libc: Path


@dataclass(frozen=True)
class ElfPatchOutcome:
    binary: Path
    runtime: RuntimePair
    backup: Path
    patch_result: ToolResult
    interpreter_result: ToolResult
    rpath_result: ToolResult
    needed_result: ToolResult

    @property
    def ok(self) -> bool:
        return (
            self.patch_result.ok
            and self.interpreter_result.ok
            and self.rpath_result.ok
            and self.needed_result.ok
        )

    def summary(self) -> str:
        state = "OK" if self.ok else "FAILED"
        return (
            f"[{state}] ELF={self.binary}\n"
            f"loader={self.runtime.loader.name}\n"
            f"libc={self.runtime.libc.name}\n"
            f"backup={self.backup}\n"
            f"interpreter={self.interpreter_result.stdout.strip() or '-'}\n"
            f"rpath={self.rpath_result.stdout.strip() or '-'}\n"
            f"needed={', '.join(self.needed_result.stdout.splitlines()) or '-'}"
        )


def is_elf_file(path: str | Path) -> bool:
    candidate = Path(path)
    try:
        if not candidate.is_file():
            return False
        with candidate.open("rb") as stream:
            return stream.read(4) == b"\x7fELF"
    except OSError:
        return False


def discover_runtime_pair(binary_path: str | Path) -> RuntimePair:
    binary = Path(binary_path)
    if not is_elf_file(binary):
        raise ValueError(f"不是有效 ELF: {binary}")
    files = [item for item in binary.parent.iterdir() if item.is_file() and item != binary]

    def loader_rank(path: Path) -> tuple[int, int, str]:
        name = path.name.lower()
        if name.startswith("ld-linux") and ".so" in name:
            rank = 0
        elif name.startswith("ld-") and ".so" in name:
            rank = 1
        elif name.startswith("ld") and ".so" in name:
            rank = 2
        else:
            rank = 99
        return rank, len(name), name

    def libc_rank(path: Path) -> tuple[int, int, str]:
        name = path.name.lower()
        if name == "libc.so.6":
            rank = 0
        elif name.startswith("libc-") and ".so" in name:
            rank = 1
        elif name.startswith("libc.so"):
            rank = 2
        else:
            rank = 99
        return rank, len(name), name

    loaders = sorted((item for item in files if loader_rank(item)[0] < 99), key=loader_rank)
    libcs = sorted((item for item in files if libc_rank(item)[0] < 99), key=libc_rank)
    if not loaders or not libcs:
        missing = []
        if not loaders:
            missing.append("ld/ld-linux")
        if not libcs:
            missing.append("libc")
        raise FileNotFoundError(f"ELF 同目录缺少 {' 和 '.join(missing)} 文件: {binary.parent}")
    return RuntimePair(loaders[0], libcs[0])


def auto_patch_elf(binary_path: str | Path, runner: WslToolRunner | None = None) -> ElfPatchOutcome:
    """Patch the original same-name ELF in place, with verified rollback."""
    binary = Path(binary_path).resolve()
    runtime = discover_runtime_pair(binary)
    runner = runner or WslToolRunner()
    backup, result = runner.patchelf(binary, runtime.loader, "$ORIGIN", runtime.libc)
    if not result.ok:
        shutil.copy2(backup, binary)
        raise RuntimeError(f"patchelf 失败，已从 {backup.name} 回滚：\n{result.combined_output()}")
    interpreter = runner.patchelf_interpreter(binary)
    rpath = runner.patchelf_rpath(binary)
    needed = runner.patchelf_needed(binary)
    expected_loader = runner.to_wsl_path(runtime.loader)
    verified = (
        interpreter.ok
        and interpreter.stdout.strip() == expected_loader
        and rpath.ok
        and "$ORIGIN" in rpath.stdout.strip()
        and needed.ok
        and runtime.libc.name in needed.stdout.splitlines()
    )
    if not verified:
        shutil.copy2(backup, binary)
        evidence = "\n".join(
            part
            for part in (
                interpreter.combined_output(),
                rpath.combined_output(),
                needed.combined_output(),
            )
            if part
        )
        raise RuntimeError(f"patchelf 验证失败，已从 {backup.name} 回滚：\n{evidence}")
    return ElfPatchOutcome(binary, runtime, backup, result, interpreter, rpath, needed)
