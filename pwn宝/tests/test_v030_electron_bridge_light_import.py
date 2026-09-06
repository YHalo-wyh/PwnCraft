"""v0.30 tests: PwnCraft rename + workspace light import.

Pins the v0.30 bridge contract additions:

* ping reports app=PwnCraft (v0.30 rebrand).
* ``import_target`` with ``light: true`` rebinds the single workspace truth
  to a previously imported ELF without re-running the WSL static pass —
  same response shape, cached facts/checksec preserved.
* switching targets via light import leaves the workspace project/target
  pointing at the newly selected ELF (one ELF, one workspace).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _write_min_elf(path: Path) -> None:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = (0x3E).to_bytes(2, "little")
    header[24:32] = (0x401000).to_bytes(8, "little")
    path.write_bytes(bytes(header))


class ElectronBridgeLightImportTests(unittest.TestCase):
    def _run_bridge(self, requests: list[dict]) -> list[dict]:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "pwnbao.electron_bridge"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            cwd=str(PROJECT_ROOT),
        )
        payload = "\n".join(json.dumps(request) for request in requests)
        out, err = proc.communicate(payload, timeout=180)
        if err.strip():
            self.fail(f"bridge stderr 非空: {err[:300]}")
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def test_ping_reports_pwncraft(self) -> None:
        messages = self._run_bridge([{"id": 1, "method": "ping", "params": {}}])
        pong = next(m for m in messages if m.get("id") == 1)
        self.assertTrue(pong["ok"])
        self.assertEqual(pong["result"]["app"], "PwnCraft")

    def test_light_import_reuses_and_rebinds_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            elf_a = root / "target_a"
            elf_b = root / "target_b"
            _write_min_elf(elf_a)
            _write_min_elf(elf_b)
            messages = self._run_bridge([
                {"id": 1, "method": "import_target", "params": {"path": str(elf_a)}},
                {"id": 2, "method": "import_target", "params": {"path": str(elf_b), "light": True}},
                # 切回 A：light 命中缓存，仍需完整重绑真值
                {"id": 3, "method": "import_target", "params": {"path": str(elf_a), "light": True}},
                {"id": 4, "method": "workspace_get", "params": {}},
            ])
            full = next(m for m in messages if m.get("id") == 1)
            light_b = next(m for m in messages if m.get("id") == 2)
            light_a = next(m for m in messages if m.get("id") == 3)
            for reply in (full, light_b, light_a):
                self.assertTrue(reply["ok"], reply.get("error"))
                # 响应形状与完整导入一致（UI 无需区分两条路径）
                for key in ("context", "facts", "static_report", "patch_summary", "patch_error", "project"):
                    self.assertIn(key, reply["result"])

            # light 导入保留完整导入的静态报告（缓存复用，而不是空报告）
            self.assertEqual(light_a["result"]["static_report"],
                             full["result"]["static_report"])

            workspace = next(m for m in messages if m.get("id") == 4)
            self.assertTrue(workspace["ok"])
            result = workspace["result"]
            # 真值最终指向 A（最后一次 light import 的目标）
            target_name = Path(result["target"]["working_binary"]).name
            self.assertEqual(target_name, "target_a")
            self.assertEqual(result["project"]["project_name"], "target_a")
            self.assertEqual(result["project"]["project_path"], str(root))

    def test_light_import_unknown_path_falls_back_to_full(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            elf = root / "fresh_target"
            _write_min_elf(elf)
            messages = self._run_bridge([
                {"id": 1, "method": "import_target", "params": {"path": str(elf), "light": True}},
            ])
            reply = next(m for m in messages if m.get("id") == 1)
            self.assertTrue(reply["ok"], reply.get("error"))
            # 缓存未命中 → 完整导入路径，静态报告仍然产出
            self.assertTrue("$ file" in reply["result"]["static_report"])
            self.assertEqual(reply["result"]["context"]["architecture"], "amd64")


if __name__ == "__main__":
    unittest.main()
