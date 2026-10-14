"""Fast tests for the stdlib-only offline AutoPwn MVP."""
import json
from pathlib import Path
import tempfile
import unittest

from pwncraft.features.autopwn.engine import (
    inspect_target, fuzz_cases, verify_candidates, read_candidates
)


class AutoPwnTests(unittest.TestCase):
    def test_reject_non_elf(self):
        with tempfile.TemporaryDirectory() as tmp:
            test = Path(tmp) / "invalid"
            test.write_bytes(b"not an elf")
            with self.assertRaises(ValueError):
                inspect_target(test)

    def test_deterministic_probe_cases(self):
        a = list(fuzz_cases(30, max_input=32))
        self.assertEqual(a, list(fuzz_cases(30, max_input=32)))
        self.assertEqual(len(a), 30)
        self.assertTrue(all(len(item) <= 32 for item in a))

    @unittest.skipUnless(Path("/bin/true").exists(), "Linux ELF required")
    def test_elf_inspect(self):
        info = inspect_target("/bin/true")
        self.assertEqual(len(info["sha256"]), 64)
        self.assertIn(info["bits"], (32, 64))

    @unittest.skipUnless(Path("/bin/true").exists(), "Linux ELF required")
    def test_candidate_winner_and_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "pass.py").write_text('print("TEST_GOAL")\n', encoding="utf-8")
            (folder / "fail.py").write_text('print("NO")\n', encoding="utf-8")
            (folder / "manifest.json").write_text(json.dumps({"candidates": [
                {"name": "fast", "script": "pass.py", "priority": 99},
                {"name": "slow", "script": "fail.py"}
            ]}), encoding="utf-8")
            result = verify_candidates("/bin/true", folder / "manifest.json", folder / "report",
                                       expected_regex="TEST_GOAL", workers=2, replays=2)
            self.assertEqual(result["winner"], "fast")
            self.assertTrue(result["replay_condition_met"])
            self.assertEqual(len(result["replays"]), 2)

    @unittest.skipUnless(Path("/bin/true").exists(), "Linux ELF required")
    def test_no_fabricated_win(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "fail.py").write_text('print("NO")\n', encoding="utf-8")
            (folder / "manifest.json").write_text(json.dumps({"candidates": [
                {"name": "only", "script": "fail.py"}
            ]}))
            result = verify_candidates("/bin/true", folder / "manifest.json", folder / "report",
                                       expected_regex="EXPECTED", workers=1, replays=1)
            self.assertIsNone(result["winner"])


if __name__ == "__main__":
    unittest.main()
