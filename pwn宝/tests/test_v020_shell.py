"""v0.20 core tests: TargetContext, workspace target section, schema roundtrip."""
from __future__ import annotations

import unittest

from pathlib import Path  # noqa: E402
from tempfile import TemporaryDirectory  # noqa: E402

from pwnbao.core.session import TargetContext, import_target  # noqa: E402
from pwnbao.core.workspace import PwnWorkspace  # noqa: E402


def _write_min_elf(path: Path) -> None:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = (0x3E).to_bytes(2, "little")
    header[24:32] = (0x401000).to_bytes(8, "little")
    path.write_bytes(bytes(header))


class TargetContextTests(unittest.TestCase):
    def test_import_creates_original_and_runtime_copies(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            elf = root / "proj" / "pwn"
            elf.parent.mkdir(parents=True)
            _write_min_elf(elf)
            context = import_target(elf, project_root=root / "proj")
            self.assertTrue(Path(context.original_binary).is_file())
            self.assertTrue(Path(context.working_binary).is_file())
            self.assertNotEqual(Path(context.original_binary), elf)
            self.assertEqual(context.primary_path, context.working_binary)
            # Original is read-only evidence; the runtime copy is writable.
            original_mode = Path(context.original_binary).stat().st_mode
            self.assertEqual(original_mode & 0o222, 0)

    def test_same_directory_libc_auto_discovery(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            elf = root / "pwn"
            _write_min_elf(elf)
            (root / "libc.so.6").write_bytes(b"libc")
            (root / "ld-linux-x86-64.so.2").write_bytes(b"ld")
            context = import_target(elf, project_root=root)
            self.assertTrue(context.libc.endswith("libc.so.6"))
            self.assertTrue(context.ld.endswith("ld-linux-x86-64.so.2"))

    def test_workspace_target_section_and_schema_roundtrip(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            elf = root / "pwn"
            _write_min_elf(elf)
            context = import_target(elf, project_root=root)
            workspace = PwnWorkspace()
            events: list[dict[str, object]] = []
            workspace.subscribe("target_changed", events.append)
            workspace.set_target(context)
            self.assertEqual(events[-1]["target_id"], context.target_id)
            self.assertEqual(workspace.binary["path"], context.working_binary)
            saved = workspace.save(root / "case")
            loaded = PwnWorkspace.load(saved)
            restored = TargetContext.from_dict(loaded.target)
            self.assertEqual(restored.sha256, context.sha256)
            self.assertEqual(loaded.binary["path"], context.working_binary)

    def test_legacy_schema1_project_still_loads(self) -> None:
        import json
        import tempfile

        workspace = PwnWorkspace()
        payload = workspace.to_dict()
        payload["schema"] = 1
        payload.pop("target", None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.pwnbao"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = PwnWorkspace.load(path)
        self.assertEqual(loaded.target, {})


if __name__ == "__main__":
    unittest.main()
