"""v0.31 tests: live heap operations (malloc/free/edit/show forms).

The operation forms are the user-facing entry of the core design rule:
用户操作 glibc，不是图。Forms only produce HeapOperation objects; all
semantics (request2size, bin search order, write provenance) are derived by
GlibcHeapEngine, and the canvas renders the resulting snapshot.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class HeapOperationBridgeTests(unittest.TestCase):
    def _run_bridge(self, requests: list[dict]) -> list[dict]:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "pwncraft.electron_bridge"],
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

    def test_malloc_form_runs_allocator_pipeline(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_operation",
             "params": {"kind": "malloc", "request_size": "0x78", "data": "AAAAAAAA"}},
        ])
        loaded = next(m for m in messages if m.get("id") == 1)
        operated = next(m for m in messages if m.get("id") == 2)
        self.assertTrue(loaded["ok"], loaded.get("error"))
        self.assertTrue(operated["ok"], operated.get("error"))
        base_steps = len(loaded["result"]["steps"])
        result = operated["result"]
        self.assertEqual(len(result["steps"]), base_steps + 1)
        appended = result["appended_operation"]
        # request2size：0x78 → 0x80，来源 top chunk，给出 chunk/user 地址
        self.assertIn("alloc(D, 0x78)", appended["title"])
        text = "\n".join(appended["explanation"])
        self.assertIn("0x80", text)
        self.assertIn("top chunk", text)
        self.assertIn("user ptr", text)

    def test_edit_offset_write_records_overwrite_edge(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_operation",
             "params": {"kind": "edit", "chunk": "A", "offset": "0x8", "data": "p64(0x91)"}},
        ])
        operated = next(m for m in messages if m.get("id") == 2)
        self.assertTrue(operated["ok"], operated.get("error"))
        appended = operated["result"]["appended_operation"]
        text = "\n".join(appended["explanation"])
        self.assertIn("OverwriteEdge", text)

    def test_unknown_kind_is_rejected_cleanly(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_operation", "params": {"kind": "teleport"}},
        ])
        operated = next(m for m in messages if m.get("id") == 2)
        self.assertFalse(operated["ok"])
        self.assertIn("不支持的堆操作", operated["error"])


if __name__ == "__main__":
    unittest.main()
