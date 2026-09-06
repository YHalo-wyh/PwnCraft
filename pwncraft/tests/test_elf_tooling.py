from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import shutil
import subprocess
import unittest

from pwncraft.core.elf_runtime import auto_patch_elf, discover_runtime_pair, is_elf_file
from pwncraft.core.pwndbg_manager import (
    PWNDBG_ASSETS,
    PWNDBG_MOGAI_COMMAND,
    PWNDBG_MOGAI_VERSION,
    PWNDBG_RELEASE_URL,
    PWNDBG_VERSION,
    PwndbgManager,
)
from pwncraft.core.wsl import ToolResult, WslToolRunner


class _FakeRunner:
    def __init__(self, interpreter_ok: bool = True):
        self.interpreter_ok = interpreter_ok
        self.calls = []

    @staticmethod
    def to_wsl_path(path) -> str:
        return "/mnt/c/challenge/" + Path(path).name

    def patchelf(self, binary, loader, rpath, libc):
        backup = Path(binary).with_name(Path(binary).name + ".bak.test")
        shutil.copy2(binary, backup)
        self.calls.append((Path(binary), Path(loader), rpath, Path(libc)))
        Path(binary).write_bytes(Path(binary).read_bytes() + b"PATCHED")
        return backup, ToolResult(["patchelf"], 0, "", "")

    def patchelf_interpreter(self, binary):
        value = self.to_wsl_path(self.calls[-1][1]) if self.interpreter_ok else "/wrong/ld.so"
        return ToolResult(["patchelf", "--print-interpreter"], 0, value + "\n", "")

    @staticmethod
    def patchelf_rpath(binary):
        return ToolResult(["patchelf", "--print-rpath"], 0, "$ORIGIN\n", "")

    def patchelf_needed(self, binary):
        return ToolResult(["patchelf", "--print-needed"], 0, self.calls[-1][3].name + "\n", "")


class ElfToolingTests(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        binary = root / "chall"
        binary.write_bytes(b"\x7fELF" + b"ORIGINAL")
        (root / "ld-2.31.so").write_bytes(b"ld")
        (root / "ld-linux-x86-64.so.2").write_bytes(b"loader")
        (root / "libc-2.31.so").write_bytes(b"old")
        (root / "libc.so.6").write_bytes(b"libc")
        return binary

    def test_runtime_discovery_and_in_place_patch_use_best_local_pair(self) -> None:
        with TemporaryDirectory() as temporary:
            binary = self._fixture(Path(temporary))
            self.assertTrue(is_elf_file(binary))
            pair = discover_runtime_pair(binary)
            self.assertEqual(pair.loader.name, "ld-linux-x86-64.so.2")
            self.assertEqual(pair.libc.name, "libc.so.6")
            runner = _FakeRunner()
            outcome = auto_patch_elf(binary, runner)
            self.assertTrue(outcome.ok)
            self.assertEqual(outcome.binary, binary.resolve())
            self.assertEqual(runner.calls[0][2], "$ORIGIN")
            self.assertTrue(binary.read_bytes().endswith(b"PATCHED"))
            self.assertTrue(outcome.backup.read_bytes().endswith(b"ORIGINAL"))

    def test_failed_verification_rolls_original_same_name_elf_back(self) -> None:
        with TemporaryDirectory() as temporary:
            binary = self._fixture(Path(temporary))
            original = binary.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "验证失败"):
                auto_patch_elf(binary, _FakeRunner(interpreter_ok=False))
            self.assertEqual(binary.read_bytes(), original)

    def test_wsl_patchelf_keeps_origin_literal_and_retargets_versioned_libc(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "chall"
            loader = root / "ld-linux-x86-64.so.2"
            libc = root / "libc-2.31.so"
            binary.write_bytes(b"ELF")
            loader.write_bytes(b"ld")
            libc.write_bytes(b"libc")
            runner = WslToolRunner()
            captured: list[tuple[str, list[str], int]] = []

            def run_tool(tool: str, args: list[str], timeout: int = 30) -> ToolResult:
                captured.append((tool, args, timeout))
                return ToolResult([tool, *args], 0, "", "")

            runner.run_tool = run_tool
            backup, result = runner.patchelf(binary, loader, "$ORIGIN", libc)

            self.assertTrue(result.ok)
            self.assertTrue(backup.is_file())
            self.assertEqual(captured[0][0], "patchelf")
            self.assertIn("$ORIGIN", captured[0][1])
            self.assertIn("--replace-needed", captured[0][1])
            replacement = captured[0][1].index("--replace-needed")
            self.assertEqual(captured[0][1][replacement + 1:replacement + 3], ["libc.so.6", "libc-2.31.so"])

    def test_wsl_runner_uses_exec_mode_to_preserve_tool_arguments(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch("pwncraft.core.wsl.subprocess.run", return_value=completed) as run:
            result = WslToolRunner().run_tool("patchelf", ["--set-rpath", "$ORIGIN", "/tmp/chall"])
        self.assertTrue(result.ok)
        self.assertEqual(
            run.call_args.args[0],
            ["wsl.exe", "--exec", "patchelf", "--set-rpath", "$ORIGIN", "/tmp/chall"],
        )

    def test_pwndbg_release_is_pinned_and_launcher_targets_wsl_portable(self) -> None:
        manager = PwndbgManager(download_root="downloads")
        spec = manager.launch_spec(r"C:\challenge\pwn")
        self.assertEqual(PWNDBG_VERSION, "2026.07.29")
        self.assertEqual(PWNDBG_RELEASE_URL, "https://github.com/pwndbg/pwndbg/releases/tag/2026.07.29")
        self.assertEqual(PWNDBG_ASSETS["x86_64"]["sha256"], "63c38b76bf8baeb44b4bc018c73ea0b05b872c2aba205ed5680892f2d65adb03")
        self.assertEqual(spec.program, "wsl.exe")
        self.assertEqual(PWNDBG_MOGAI_COMMAND, "pwndbg-mogai")
        self.assertEqual(PWNDBG_MOGAI_VERSION, "2026.07.29-pwndbg-mogai.16")
        self.assertIn('exec "$HOME/.local/bin/pwndbg-mogai"', spec.arguments[-1])
        self.assertIn("/mnt/c/challenge/pwn", spec.arguments[-1])
        self.assertEqual(spec.pty_command, spec.arguments)
        self.assertIn("$HOME/.local/share/pwncraft/pwndbg-mogai", spec.extension_wsl_path)
        self.assertNotIn("source ", spec.arguments[-1])
        self.assertIn("-nx", spec.arguments[-1])
        self.assertIn("-iex 'set debuginfod enabled off'", spec.arguments[-1])
        self.assertNotIn("-ex starti", spec.arguments[-1])
        self.assertEqual(spec.target_architecture, "unknown")
        self.assertFalse(spec.auto_start)

    def test_pwndbg_foreign_architecture_stays_static_while_x86_auto_starts(self) -> None:
        manager = PwndbgManager(download_root="downloads")
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            aarch64 = root / "arm64"
            x86_64 = root / "amd64"
            for path, machine in ((aarch64, 0xB7), (x86_64, 0x3E)):
                header = bytearray(64)
                header[:6] = b"\x7fELF\x02\x01"
                header[18:20] = machine.to_bytes(2, "little")
                path.write_bytes(header)

            arm_spec = manager.launch_spec(aarch64)
            x86_spec = manager.launch_spec(x86_64)

        # 用户口径（pwndbg_manager.launch_spec）：任何架构都不自动 start——
        # 程序什么时候跑、断在哪，由用户自己决定。x86 与外来架构行为一致。
        self.assertEqual(arm_spec.target_architecture, "aarch64")
        self.assertFalse(arm_spec.auto_start)
        self.assertNotIn("-ex starti", arm_spec.arguments[-1])
        self.assertEqual(x86_spec.target_architecture, "x86_64")
        self.assertFalse(x86_spec.auto_start)
        self.assertNotIn("-ex starti", x86_spec.arguments[-1])

    def test_cross_host_windows_and_native_paths_convert_without_resolve_corruption(self) -> None:
        runner = WslToolRunner()
        self.assertEqual(runner.to_wsl_path(r"C:\challenge\pwn"), "/mnt/c/challenge/pwn")
        self.assertEqual(
            runner.to_wsl_path(r"C:\Users\WYH\Desktop\a b\pwn"),
            "/mnt/c/Users/WYH/Desktop/a b/pwn",
        )
        self.assertEqual(
            runner.to_wsl_path(r"D:\CTF\中文目录\pwn"),
            "/mnt/d/CTF/中文目录/pwn",
        )
        self.assertEqual(runner.to_wsl_path("/mnt/c/foo"), "/mnt/c/foo")
        self.assertEqual(runner.to_wsl_path("/tmp/pwn"), "/tmp/pwn")


if __name__ == "__main__":
    unittest.main()
