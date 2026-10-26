"""社区通防 Patcher（evilPatcher / elf-seccomp-patcher）+ seccomp_scan RPC 的真值单测。

不依赖 WSL / 真实工具：runner 全部用假件，包装模块断言 argv 形状、scratch
隔离、预设/flag 组合与输出落盘；桥测直接进程内实例化 ElectronBridge 并 mock
_patch_lab / _triage_seccomp / 包装模块的 run。
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from pwncraft.core.wsl import ToolResult, WslToolRunner
from pwncraft.features.patch import patchers
from pwncraft.features.patch.patchers import common, elfseccomp, evilpatcher
from pwncraft.features.patch.recipes import RECIPE_CATALOG
from pwncraft.electron_bridge import ElectronBridge


def _write_min_elf(path: Path, fill: int = 0x90) -> Path:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = (0x3E).to_bytes(2, "little")
    header[24:32] = (0x401000).to_bytes(8, "little")
    path.write_bytes(bytes(header) + bytes([fill]) * 32)
    return path


def _wsl_to_windows(wsl_path: str) -> Path:
    """将 runner 的 Linux 路径还原为测试宿主路径，兼容 Windows 和 Linux CI。"""
    if os.name != "nt":
        return Path(wsl_path)
    parts = Path(wsl_path).parts          # ('/', 'mnt', 'f', ...)
    if len(parts) < 3 or parts[1] != "mnt":
        raise AssertionError(f"argv 路径必须是 /mnt 形式: {wsl_path}")
    drive, rest = parts[2].upper(), parts[3:]
    return Path(f"{drive}:\\", *rest)


class DiffRunsTests(unittest.TestCase):
    def test_equal_size_diff_runs(self):
        old = b"\x00\x01\x02\x03\x04"
        new = b"\x00\xFF\xFF\x02\x04"
        report = common.diff_runs(old, new)
        self.assertTrue(report["same_size"])
        self.assertFalse(report["truncated"])
        self.assertEqual(report["changed"], 3)
        self.assertEqual(len(report["runs"]), 1)
        first = report["runs"][0]
        self.assertEqual(first["offset"], 1)
        self.assertEqual(first["length"], 3)
        self.assertEqual(first["old"], "01 02 03")
        self.assertEqual(first["new"], "ff ff 02")

    def test_identical_bytes_yield_zero_changed(self):
        report = common.diff_runs(b"abc", b"abc")
        self.assertEqual(report["changed"], 0)
        self.assertEqual(report["runs"], [])

    def test_size_mismatch_reports_without_runs(self):
        report = common.diff_runs(b"abc", b"abcd")
        self.assertFalse(report["same_size"])
        self.assertEqual(report["changed"], -1)
        self.assertEqual(report["runs"], [])

    def test_truncation_cap(self):
        old = bytes(16)
        new = bytes(0xFF if index % 2 else 0 for index in range(16))
        report = common.diff_runs(old, new, max_runs=4)
        self.assertTrue(report["truncated"])
        self.assertEqual(len(report["runs"]), 4)


class ResolveOutputTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.source = _write_min_elf(self.folder / "pwn")

    def tearDown(self):
        self._tmp.cleanup()

    def test_defaults_to_source_dir_and_name(self):
        product = self.folder / "prod.bin"
        product.write_bytes(b"patched")
        out = common.resolve_output(product, self.source, "", "", "pwn.patch")
        self.assertEqual(out, self.source.parent / "pwn.patch")
        self.assertEqual(out.read_bytes(), b"patched")

    def test_custom_dir_and_name(self):
        target_dir = self.folder / "out"
        product = self.folder / "prod.bin"
        product.write_bytes(b"x")
        out = common.resolve_output(product, self.source, str(target_dir), "own.pwn", "pwn.patch")
        self.assertEqual(out, target_dir / "own.pwn")

    def test_name_with_separator_rejected(self):
        with self.assertRaises(ValueError):
            common.resolve_output(self.source, self.source, "", r"sub\dir.pwn", "pwn.patch")
        with self.assertRaises(ValueError):
            common.resolve_output(self.source, self.source, "", "sub/dir.pwn", "pwn.patch")

    def test_protected_paths_never_overwritten(self):
        original = _write_min_elf(self.folder / "pwn_orig")
        product = self.folder / "prod.bin"
        product.write_bytes(b"x")
        with self.assertRaises(ValueError):
            common.resolve_output(product, self.source, str(self.folder),
                                  "pwn_orig", "pwn.patch", protected=(original,))


class RegistryTests(unittest.TestCase):
    def test_catalog_lists_both_patchers_with_presets(self):
        entries = patchers.catalog()
        by_id = {item["id"]: item for item in entries}
        self.assertIn("evilpatcher", by_id)
        self.assertIn("elfseccomp", by_id)
        self.assertEqual(by_id["evilpatcher"]["output_suffix"], ".patch")
        self.assertEqual(by_id["elfseccomp"]["output_suffix"], ".protected")
        evil_ids = {p["id"] for p in by_id["evilpatcher"]["presets"]}
        self.assertIn("custom", evil_ids)
        seccomp_ids = [p["id"] for p in by_id["elfseccomp"]["presets"]]
        self.assertEqual(seccomp_ids, ["default", "strict", "networked", "custom"])

    def test_get_rejects_unknown(self):
        with self.assertRaises(ValueError):
            patchers.get("nope")


class SandboxPresetsTests(unittest.TestCase):
    def test_vendored_presets_are_listed(self):
        presets = evilpatcher._sandbox_presets()
        self.assertGreaterEqual(len(presets), 4)
        ids = {item["id"] for item in presets}
        self.assertIn("sandbox1", ids)
        for item in presets:
            self.assertIn("A = sys_number", item["code"])
            self.assertTrue((evilpatcher.tool_dir() / "sandboxs" / f"{item['id']}.asm").is_file())

    def test_missing_tool_dir_reports_empty_presets(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict("os.environ", {"PWNCRAFT_EVILPATCHER_DIR": str(Path(tmp) / "nope")}):
            self.assertEqual(evilpatcher._sandbox_presets(), [])


class EvilPatcherRunTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.binary = _write_min_elf(self.folder / "pwn")

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_runner(self, patched_offsets=(70, 71, 72)):
        def fake_run_wsl_argv(argv, timeout=120):
            script, elf = Path(argv[1]), Path(argv[2])
            self.assertEqual(argv[0], "python3")
            self.assertEqual(script.name, "evilPatcher.py")
            self.assertEqual(elf.parent.name, "evilpatcher")
            for item in argv[1:4]:
                self.assertTrue(str(item).startswith("/"), item)
                self.assertNotIn("\\", str(item))
            self.assertEqual(argv[4], "1")
            win_elf = _wsl_to_windows(argv[2])
            patched = bytearray(win_elf.read_bytes())
            for offset in patched_offsets:
                patched[offset] = 0xAA
            (win_elf.parent / (win_elf.name + ".patch")).write_bytes(bytes(patched))
            return ToolResult(argv, 0, "Patch file successfully!!!", "")
        runner = WslToolRunner()
        return runner, fake_run_wsl_argv

    def test_run_custom_policy_writes_output_and_diff(self):
        runner, fake = self._fake_runner()
        before = self.binary.read_bytes()
        with patch.object(WslToolRunner, "run_wsl_argv", side_effect=fake):
            result = evilpatcher.run(self.binary,
                                     {"preset": "custom", "policy": "A = sys_number\nreturn ALLOW"},
                                     runner, timeout=120)
        self.assertTrue(result["ok"])
        self.assertEqual(result["changed_bytes"], 3)
        self.assertEqual(len(result["diff"]), 1)
        self.assertIn("A = sys_number", result["sandbox"])
        # 输出默认落源文件目录，文件名 = <名>.patch；工作副本本体未被改动
        self.assertEqual(Path(result["output_path"]), self.folder / "pwn.patch")
        self.assertTrue(Path(result["output_path"]).is_file())
        self.assertEqual(self.binary.read_bytes(), before)

    def test_run_preset_resolves_vendored_rule(self):
        runner, fake = self._fake_runner()
        with patch.object(WslToolRunner, "run_wsl_argv", side_effect=fake):
            result = evilpatcher.run(self.binary, {"preset": "sandbox1"}, runner)
        self.assertIn("A == execve", result["sandbox"])

    def test_run_custom_output_dir_and_name(self):
        runner, fake = self._fake_runner()
        out_dir = self.folder / "elsewhere"
        with patch.object(WslToolRunner, "run_wsl_argv", side_effect=fake):
            result = evilpatcher.run(self.binary, {
                "preset": "mini_sandbox", "output_dir": str(out_dir),
                "output_name": "final.bin"}, runner)
        self.assertEqual(Path(result["output_path"]), out_dir / "final.bin")

    def test_run_protects_working_copy_from_output_overwrite(self):
        runner, fake = self._fake_runner()
        with patch.object(WslToolRunner, "run_wsl_argv", side_effect=fake):
            # 输出名与工作副本同名 → 必须拒绝，绝不能覆盖工作副本本身
            with self.assertRaises(ValueError):
                evilpatcher.run(self.binary, {"preset": "mini_sandbox",
                                              "output_name": self.binary.name,
                                              "_protected": [str(self.binary)]}, runner)

    def test_run_rejects_empty_custom_policy(self):
        with self.assertRaises(ValueError):
            evilpatcher.run(self.binary, {"preset": "custom", "policy": "   "}, Mock())

    def test_run_rejects_unknown_preset(self):
        with self.assertRaises(ValueError):
            evilpatcher.run(self.binary, {"preset": "sandbox9"}, Mock())

    def test_run_reports_missing_tool(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict("os.environ", {"PWNCRAFT_EVILPATCHER_DIR": str(Path(tmp) / "nope")}):
            with self.assertRaises(ValueError) as ctx:
                evilpatcher.run(self.binary, {"preset": "mini_sandbox"}, Mock())
            self.assertIn("未找到 evilPatcher", str(ctx.exception))

    def test_missing_pwntools_maps_to_install_hint(self):
        error = evilpatcher._friendly_error(
            ToolResult([], 1, "", "Traceback ... ModuleNotFoundError: No module named 'pwn'"), 5)
        self.assertIn("pip install pwntools", error)


class ElfSeccompRunTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.binary = _write_min_elf(self.folder / "pwn")

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_runner(self):
        def fake_run_wsl_argv(argv, timeout=120):
            self.assertEqual(argv[0], "python3")
            self.assertEqual(Path(argv[1]).name, "patcher.py")
            self.assertEqual(argv[3], "-o")
            # input/-o 的路径分量必须是已翻译的 /mnt 形式；flag 在 -o 之后
            for item in (argv[1], argv[2], argv[4]):
                self.assertTrue(str(item).startswith("/"), item)
            win_in, win_out = _wsl_to_windows(argv[2]), _wsl_to_windows(argv[4])
            patched = bytearray(win_in.read_bytes())
            patched[80], patched[81] = 0x5A, 0xA5
            win_out.write_bytes(bytes(patched))
            return ToolResult(argv, 0, "patched ok", "")
        return WslToolRunner(), fake_run_wsl_argv

    def test_default_preset_builds_minimal_argv_and_output(self):
        runner, fake = self._fake_runner()
        with patch.object(WslToolRunner, "run_wsl_argv", side_effect=fake):
            result = elfseccomp.run(self.binary, {"preset": "default"}, runner)
        self.assertTrue(result["ok"])
        self.assertEqual(result["changed_bytes"], 2)
        self.assertEqual(result["flags"],
                         {"single_threaded": False, "deny_open": False,
                          "allow_connect": False, "no_default_paths": False})
        self.assertEqual(Path(result["output_path"]), self.folder / "pwn.protected")

    def test_strict_preset_and_extra_flags_merge(self):
        runner, fake = self._fake_runner()
        captured = {}
        base = self._fake_runner()[1]

        def spy(argv, timeout=120):
            captured.update(flags=[a for a in argv if a.startswith("--")])
            return base(argv, timeout=timeout)

        with patch.object(WslToolRunner, "run_wsl_argv", side_effect=spy):
            result = elfseccomp.run(self.binary, {
                "preset": "strict", "allow_connect": True}, runner)
        self.assertIn("--single-threaded", captured["flags"])
        self.assertIn("--deny-open", captured["flags"])
        self.assertIn("--allow-connect", captured["flags"])
        self.assertTrue(result["flags"]["allow_connect"])

    def test_extra_flags_whitelist(self):
        with self.assertRaises(ValueError):
            elfseccomp.run(self.binary, {"preset": "custom", "extra_flags": "--sudo"}, Mock())

    def test_path_options_are_passed_and_validated(self):
        runner, fake = self._fake_runner()
        captured = {}

        def spy(argv, timeout=120):
            captured.update(argv=list(argv))
            return fake(argv, timeout=timeout)

        with patch.object(WslToolRunner, "run_wsl_argv", side_effect=spy):
            elfseccomp.run(self.binary, {
                "preset": "default", "protected_path": "/game/flag",
                "allow_ro": "/opt/a, /opt/b", "allow_rw": "/srv/data"}, runner)
        argv = captured["argv"]
        self.assertEqual(argv[argv.index("--protected-path") + 1], "/game/flag")
        self.assertEqual(argv[argv.index("--allow-ro") + 1], "/opt/a")
        self.assertEqual(argv[argv.index("--allow-ro") + 3], "/opt/b")
        self.assertEqual(argv[argv.index("--allow-rw") + 1], "/srv/data")
        with self.assertRaises(ValueError):
            elfseccomp._split_paths("C:/Windows", "allow_ro")

    def test_missing_product_maps_to_hint(self):
        runner = Mock()
        runner.run_wsl_argv.return_value = ToolResult([], 0, "", "")
        with self.assertRaises(ValueError) as ctx:
            elfseccomp.run(self.binary, {"preset": "default"}, runner)
        self.assertIn("未产出补丁文件", str(ctx.exception))
        runner.run_wsl_argv.return_value = ToolResult([], 1, "", "boom")
        with self.assertRaises(ValueError) as ctx:
            elfseccomp.run(self.binary, {"preset": "default"}, runner)
        self.assertIn("退出码 1", str(ctx.exception))

    def test_missing_lief_maps_to_install_hint(self):
        error = elfseccomp._friendly_error(
            ToolResult([], 1, "", "ModuleNotFoundError: No module named 'lief'"), 5)
        self.assertIn("pip install", error)
        self.assertIn("lief", error)


class WslRunnerGuardTests(unittest.TestCase):
    def test_empty_argv_is_rejected_without_spawning(self):
        with self.assertRaises(ValueError):
            WslToolRunner().run_wsl_argv([])


class RecipeCatalogTests(unittest.TestCase):
    def test_patcher_card_exists_with_all_fields(self):
        cards = [r for r in RECIPE_CATALOG if r["id"] == "patcher"]
        self.assertEqual(len(cards), 1)
        keys = [f["key"] for f in cards[0]["fields"]]
        for key in ("patcher", "preset", "policy", "protected_path", "allow_ro",
                    "allow_rw", "extra_flags", "output_dir", "output_name"):
            self.assertIn(key, keys)
        self.assertTrue(any("互斥" in w for w in cards[0]["warnings"]))


class BridgePatcherTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.binary = _write_min_elf(self.folder / "pwn")
        self.bridge = ElectronBridge()
        self.lab = Mock()
        self.lab.binary = self.binary
        self.bridge._patch_lab = Mock(return_value=self.lab)

    def tearDown(self):
        self._tmp.cleanup()

    def test_recipes_surface_patcher_catalog(self):
        result = self.bridge.rpc_patch_recipes({})
        ids = [r["id"] for r in result["recipes"]]
        self.assertIn("patcher", ids)
        entries = result["patchers"]
        self.assertEqual({item["id"] for item in entries}, {"evilpatcher", "elfseccomp"})

    def test_run_defaults_output_dir_to_source_parent(self):
        orig_dir = self.folder / "orig"
        orig_dir.mkdir()
        original = _write_min_elf(orig_dir / "pwn")
        self.bridge._patch_target = Mock(return_value={"original_binary": str(original)})
        with patch.object(evilpatcher, "run", return_value={"ok": True}) as fake_run:
            self.bridge.rpc_patcher_run({"path": str(self.binary), "patcher": "evilpatcher",
                                         "preset": "mini_sandbox"})
        options = fake_run.call_args[0][1]
        self.assertEqual(options["output_dir"], str(original.parent))
        self.assertIn(str(self.binary), options["_protected"])
        self.assertIn(str(original), options["_protected"])

    def test_run_respects_explicit_output_dir(self):
        self.bridge._patch_target = Mock(return_value={})
        with patch.object(evilpatcher, "run", return_value={"ok": True}) as fake_run:
            self.bridge.rpc_patcher_run({"path": str(self.binary), "patcher": "evilpatcher",
                                         "preset": "mini_sandbox",
                                         "output_dir": "D:/out"})
        self.assertEqual(fake_run.call_args[0][1]["output_dir"], "D:/out")

    def test_run_forwards_options_and_rejects_unknown_patcher(self):
        self.bridge._patch_target = Mock(return_value={})
        with patch.object(evilpatcher, "run", return_value={"ok": True}) as fake_run:
            self.bridge.rpc_patcher_run({
                "path": str(self.binary), "patcher": "evilpatcher",
                "preset": "custom", "policy": "A = sys_number",
                "output_name": "out.patch", "noise": "dropped"})
        options = fake_run.call_args[0][1]
        self.assertEqual(options["preset"], "custom")
        self.assertEqual(options["policy"], "A = sys_number")
        self.assertEqual(options["output_name"], "out.patch")
        self.assertNotIn("noise", options)
        with self.assertRaises(ValueError):
            self.bridge.rpc_patcher_run({"path": str(self.binary), "patcher": "nope"})

    def test_adopt_replaces_working_copy_with_backup(self):
        before = self.binary.read_bytes()
        patched = bytearray(before)
        patched[64] = 0x5A
        output = self.folder / "out.protected"
        output.write_bytes(bytes(patched))
        self.bridge._disasm_cache["k"] = [{"sentinel": True}]
        result = self.bridge.rpc_patcher_adopt(
            {"path": str(self.binary), "output_path": str(output)})
        self.assertEqual(self.binary.read_bytes(), bytes(patched))
        backup = Path(result["backup"])
        self.assertTrue(backup.is_file())
        self.assertEqual(backup.read_bytes(), before)  # 备份保存采纳前的原工作副本
        self.assertEqual(self.bridge._disasm_cache, {})

    def test_adopt_missing_output_rejected(self):
        with self.assertRaises(ValueError):
            self.bridge.rpc_patcher_adopt(
                {"path": str(self.binary), "output_path": str(self.folder / "ghost.patch")})


class BridgeSeccompScanTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)
        self.binary = _write_min_elf(self.folder / "pwn")
        self.bridge = ElectronBridge()

    def tearDown(self):
        self._tmp.cleanup()

    def test_scan_clamps_timeout_and_resolves_path(self):
        with patch.object(self.bridge, "_triage_seccomp",
                          return_value={"status": "done"}) as fake:
            self.bridge.rpc_seccomp_scan({"path": str(self.binary), "timeout": "99"})
            self.assertEqual(fake.call_args.args[0], self.binary.resolve())
            self.assertEqual(fake.call_args.kwargs.get("timeout"), 60)
            self.bridge.rpc_seccomp_scan({"path": str(self.binary), "timeout": "abc"})
            self.assertEqual(fake.call_args.kwargs.get("timeout"), 12)

    def test_scan_rejects_non_elf(self):
        decoy = self.folder / "decoy.txt"
        decoy.write_text("hello")
        with self.assertRaises(ValueError):
            self.bridge.rpc_seccomp_scan({"path": str(decoy)})


if __name__ == "__main__":
    unittest.main()
