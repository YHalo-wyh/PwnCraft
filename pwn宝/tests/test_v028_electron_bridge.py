"""v0.28 tests: Electron bridge — stdio JSON-RPC over the shared truth core.

The Electron surface never re-implements Pwn truth; these tests pin the
bridge contract (hello event, ping, full import_target flow, workspace
propagation) using the same minimal-ELF fixture as the session tests.
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


class ElectronBridgeTests(unittest.TestCase):
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
        out, err = proc.communicate(payload, timeout=120)
        if err.strip():
            self.fail(f"bridge stderr 非空: {err[:300]}")
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def test_hello_ping_roundtrip(self) -> None:
        messages = self._run_bridge([{"id": 1, "method": "ping", "params": {}}])
        hello = [m for m in messages if m.get("event") == "hello"]
        self.assertTrue(hello, "缺少 hello 事件")
        pong = next(m for m in messages if m.get("id") == 1)
        self.assertTrue(pong["ok"])
        self.assertTrue(pong["result"]["version"].startswith("v0.3"))
        self.assertEqual(pong["result"]["app"], "PwnCraft")

    def test_unknown_method_is_rejected_cleanly(self) -> None:
        messages = self._run_bridge([{"id": 7, "method": "nope", "params": {}}])
        reply = next(m for m in messages if m.get("id") == 7)
        self.assertFalse(reply["ok"])
        self.assertIn("未知方法", reply["error"])

    def test_import_target_full_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            elf = root / "pwn"
            _write_min_elf(elf)
            messages = self._run_bridge([
                {"id": 1, "method": "import_target", "params": {"path": str(elf)}},
                {"id": 2, "method": "workspace_get", "params": {}},
            ])
            imported = next(m for m in messages if m.get("id") == 1)
            self.assertTrue(imported["ok"], imported.get("error"))
            result = imported["result"]
            self.assertTrue(Path(result["context"]["working_binary"]).is_file())
            self.assertTrue(result["context"]["working_binary"].endswith(".pwnbao\\runtime\\pwn")
                            or ".pwnbao/runtime/pwn" in result["context"]["working_binary"])
            self.assertEqual(result["context"]["architecture"], "amd64")
            self.assertTrue("$ file" in result["static_report"])

            workspace = next(m for m in messages if m.get("id") == 2)
            self.assertTrue(workspace["ok"])
            self.assertEqual(workspace["result"]["project"]["project_name"], "pwn")
            self.assertEqual(workspace["result"]["project"]["project_path"], str(root))

            # 原始副本只读（Single Truth 约定）
            original = Path(result["context"]["original_binary"])
            self.assertEqual(original.stat().st_mode & 0o222, 0)

    def test_import_rejects_non_elf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            junk = Path(tmp) / "not_an_elf.txt"
            junk.write_text("hello", encoding="utf-8")
            messages = self._run_bridge([
                {"id": 1, "method": "import_target", "params": {"path": str(junk)}},
            ])
            reply = next(m for m in messages if m.get("id") == 1)
            self.assertFalse(reply["ok"])
            self.assertIn("ELF", reply["error"])


if __name__ == "__main__":
    unittest.main()
