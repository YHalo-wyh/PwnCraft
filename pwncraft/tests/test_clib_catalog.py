"""C 函数速查目录（clib_catalog.json）加载/校验/搜索 + bridge RPC 契约测试。

目录数据按用户 C 语言笔记的结构组织（原型 + 参数逐项说明 + 返回值 + pwn 笔记），
这里是 Truth 层的守门测试：缺原型、重名、未知键都要在校验期失败，而不是上屏。
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pwncraft.core.models import CFunctionCatalog, CatalogValidationError  # noqa: E402

# 用户笔记（C语言.md）中明确记录过的函数——一个都不能少
NOTE_FUNCTIONS = (
    "printf", "sprintf", "snprintf", "__printf_chk", "fgets", "scanf", "getrandom",
    "strchr", "strcmp", "memset", "memcpy", "open", "read", "write", "realloc",
    "strtol", "strtoul", "__errno_location",
)

# 扩充批次：进程 / 网络 / 内存保护 / 常见字符串与 IO 族的抽查
EXPANDED_FUNCTIONS = (
    "system", "execve", "execl", "execvp", "fork", "waitpid", "exit", "_exit",
    "popen", "sleep", "socket", "connect", "bind", "listen", "accept", "send",
    "recv", "dup2", "pipe", "mmap", "mprotect", "munmap", "malloc_usable_size",
    "strncpy", "strncmp", "strcat", "strncat", "strdup", "strstr", "strrchr",
    "strtok", "strcasecmp", "memmove", "memcmp", "fprintf", "sscanf", "fread",
    "fwrite", "fputs", "gets", "getchar", "putchar", "fflush", "fclose",
    "perror", "strerror", "strtoull", "time", "getenv", "signal",
)


class CFunctionCatalogTests(unittest.TestCase):
    def test_load_default_contains_note_functions(self) -> None:
        catalog = CFunctionCatalog.load_default()
        names = {fn.name for fn in catalog.functions}
        for expected in NOTE_FUNCTIONS:
            self.assertIn(expected, names, f"缺少笔记中的函数: {expected}")
        for expected in EXPANDED_FUNCTIONS:
            self.assertIn(expected, names, f"缺少扩充函数: {expected}")
        self.assertGreaterEqual(len(catalog.functions), 75)
        self.assertGreaterEqual(len(catalog.operators), 4)

    def test_every_function_has_prototype_and_category(self) -> None:
        catalog = CFunctionCatalog.load_default()
        for fn in catalog.functions:
            self.assertTrue(fn.name)
            self.assertTrue(fn.prototype.rstrip().endswith(";"), fn.name)
            self.assertTrue(fn.category, fn.name)
            for ret in fn.returns:
                self.assertTrue(ret.value)

    def test_search_covers_param_notes_and_tags(self) -> None:
        catalog = CFunctionCatalog.load_default()
        # “低 8 位”只出现在 memset 的参数说明里——搜索必须命中参数 note
        self.assertTrue(any(fn.name == "memset" for fn in catalog.search("低 8 位")))
        self.assertTrue(any(fn.name == "__printf_chk" for fn in catalog.search("fortify")))
        self.assertTrue(any(fn.name == "read" for fn in catalog.search("orw")))

    def test_operators_short_circuit_flags(self) -> None:
        catalog = CFunctionCatalog.load_default()
        by_symbol = {op.symbol: op for op in catalog.operators}
        self.assertTrue(by_symbol["&&"].short_circuit)
        self.assertTrue(by_symbol["||"].short_circuit)
        self.assertFalse(by_symbol["&"].short_circuit)
        self.assertFalse(by_symbol["|"].short_circuit)

    def test_categories_are_returned_in_order(self) -> None:
        categories = CFunctionCatalog.load_default().categories()
        for expected in ("输入输出", "内存", "进程执行", "网络套接字"):
            self.assertIn(expected, categories)
        self.assertEqual(len(categories), len(set(categories)))

    def test_duplicate_names_rejected(self) -> None:
        payload = {
            "functions": [
                {"name": "read", "prototype": "int read(void);"},
                {"name": "read", "prototype": "int read(void);"},
            ],
            "operators": [],
        }
        with self.assertRaises(CatalogValidationError):
            CFunctionCatalog._validate_payload(payload)

    def test_missing_prototype_rejected(self) -> None:
        payload = {"functions": [{"name": "read"}], "operators": []}
        with self.assertRaises(CatalogValidationError):
            CFunctionCatalog._validate_payload(payload)

    def test_unknown_keys_rejected(self) -> None:
        payload = {
            "functions": [{"name": "read", "prototype": "int read(void);", "bogus": 1}],
            "operators": [],
        }
        with self.assertRaises(CatalogValidationError):
            CFunctionCatalog._validate_payload(payload)

    def test_param_without_name_rejected(self) -> None:
        payload = {
            "functions": [{"name": "read", "prototype": "int read(void);", "params": [{"note": "x"}]}],
            "operators": [],
        }
        with self.assertRaises(CatalogValidationError):
            CFunctionCatalog._validate_payload(payload)

    def test_return_without_value_rejected(self) -> None:
        payload = {
            "functions": [{"name": "read", "prototype": "int read(void);", "returns": [{"condition": "成功"}]}],
            "operators": [],
        }
        with self.assertRaises(CatalogValidationError):
            CFunctionCatalog._validate_payload(payload)


class ClibBridgeRpcTests(unittest.TestCase):
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
        out, err = proc.communicate(payload, timeout=180)
        if err.strip():
            self.fail(f"bridge stderr 非空: {err[:300]}")
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def test_rpc_clib_catalog_contract(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "clib_catalog", "params": {}},
            {"id": 2, "method": "clib_catalog", "params": {"query": "memset"}},
        ])
        listing = next(m for m in messages if m.get("id") == 1)
        self.assertTrue(listing["ok"])
        result = listing["result"]
        self.assertGreaterEqual(result["count"], 75)
        self.assertTrue(result["categories"])
        self.assertTrue(result["operators"])
        fn = next(f for f in result["functions"] if f["name"] == "read")
        self.assertTrue(fn["prototype"].endswith(";"))
        self.assertTrue(fn["params"], "read 必须有参数说明")
        self.assertTrue(any("fd" == p["name"] for p in fn["params"]))
        self.assertTrue(fn["returns"], "read 必须有返回值说明")

        searched = next(m for m in messages if m.get("id") == 2)
        self.assertTrue(searched["ok"])
        names = [f["name"] for f in searched["result"]["functions"]]
        self.assertIn("memset", names)


if __name__ == "__main__":
    unittest.main()
