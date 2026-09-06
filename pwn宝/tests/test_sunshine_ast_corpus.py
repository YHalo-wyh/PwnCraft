from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pwnbao.tools.sunshine_ast_corpus import _candidate_paths, evaluate_file


class SunshineAstCorpusTests(unittest.TestCase):
    def test_inventory_and_per_exp_replay_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exp = root / "challenge" / "exp.py"
            exp.parent.mkdir()
            exp.write_text(
                """
def add(idx, size):
    io.sendline(b'1')
    io.sendline(str(idx).encode())
    io.sendline(str(size).encode())

add(0, 0x40)
""",
                encoding="utf-8",
            )
            (root / "challenge" / "helper.py").write_text("print('not an EXP')\n", encoding="utf-8")
            self.assertEqual(_candidate_paths(root), [exp])
            output = root / "artifacts"
            row = evaluate_file(exp, root, output)
            self.assertEqual(row["model_status"], "FULL_REPLAY")
            self.assertFalse(row["semantic_verified"])
            self.assertEqual(row["operation_kinds"], {"alloc": 1})
            self.assertTrue((output / str(row["artifact"])).is_file())


if __name__ == "__main__":
    unittest.main()
