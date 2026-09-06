"""v0.21 Phase D/E tests: physical grid, edit transactions, semantic lens."""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pwnbao.core.lens import call_lens, render_lens, syscall_lens  # noqa: E402
from pwnbao.features.heapviz.editing import EditTransaction, TransactionStack  # noqa: E402
from pwnbao.features.heapviz.grid import (  # noqa: E402
    build_chunk_rows,
    covered_fraction,
    intersect_coverage,
    rows_touching,
    virtualize,
)


class PhysicalGridTests(unittest.TestCase):
    def test_amd64_row_layout_is_canonical(self) -> None:
        rows = build_chunk_rows(0x20, 8, chunk_id="A")
        self.assertEqual(
            [(r.role, r.start, r.end) for r in rows],
            [("prev_size", 0, 8), ("size", 8, 16), ("user", 16, 32)],
        )
        user_row = rows[2]
        self.assertEqual([cell.column for cell in user_row.cells], [0, 1])
        self.assertEqual(user_row.cells[0].start, 16)
        self.assertEqual(user_row.cells[1].end, 32)

    def test_partial_tail_row_is_clamped(self) -> None:
        rows = build_chunk_rows(0x18, 8, chunk_id="B")
        self.assertEqual(rows[-1].role, "user")
        self.assertEqual(rows[-1].end, 0x18)
        self.assertEqual(len(rows[-1].cells), 1)  # 只有左 qword

    def test_coverage_intersects_existing_rows_only(self) -> None:
        rows = build_chunk_rows(0x30, 8, chunk_id="B")
        # 覆盖 0x18 从 chunk 头开始：prev_size+size+user0 前一半
        spans = intersect_coverage(rows, 0, 0x18)
        self.assertEqual(
            [(row.row_id, start, end) for row, start, end in spans],
            [("B.prev_size", 0, 8), ("B.size", 8, 16), ("B.user0", 16, 24)],
        )
        # 行数不随 coverage 长度增加（§30：不是新的视觉行）
        self.assertEqual(len(build_chunk_rows(0x30, 8)), 4)

    def test_covered_fraction_is_proportional_mask(self) -> None:
        row = build_chunk_rows(0x20, 8, chunk_id="A")[2]
        left, right = covered_fraction(16, 24, row)  # 只覆盖左 qword
        self.assertEqual((left, right), (0.0, 0.5))

    def test_virtualize_reports_collapsed_bytes(self) -> None:
        rows = build_chunk_rows(0x110, 8, chunk_id="BIG", max_user_rows=2)
        visible, collapsed = virtualize(rows, 0x110, keep_tail_rows=1)
        self.assertLess(len(visible), len(build_chunk_rows(0x110, 8)))
        self.assertGreater(collapsed, 0)
        self.assertTrue(rows_touching(rows, 0, 0x40))
        self.assertFalse(rows_touching((), 0, 0x10))


class EditTransactionTests(unittest.TestCase):
    def test_lifecycle_preview_validate_commit(self) -> None:
        transaction = EditTransaction(subject_id="A", direction="s", start=0x30)
        transaction.preview(0x40)
        self.assertTrue(transaction.is_draft)
        self.assertEqual(transaction.validate(), ())
        applied = []
        stack = TransactionStack(apply_patch=lambda patch: applied.append(patch))
        patch = stack.commit(transaction)
        self.assertIsNotNone(patch)
        self.assertEqual((patch.start, patch.end), (0x30, 0x40))
        self.assertEqual(applied, [patch])
        self.assertEqual(stack.undo_depth, 1)
        self.assertEqual(stack.redo_depth, 0)

    def test_invalid_payload_blocks_commit(self) -> None:
        transaction = EditTransaction(subject_id="A", direction="s", start=0x30)
        transaction.preview(0x38, payload=b"A" * 16)  # 超范围
        self.assertTrue(transaction.validate())
        self.assertIsNone(transaction.commit())

    def test_undo_and_redo_are_semantic_only(self) -> None:
        stack = TransactionStack()
        transaction = EditTransaction(subject_id="A", direction="s", start=0x30)
        transaction.preview(0x48)
        stack.commit(transaction)
        undone = stack.undo()
        self.assertIsNotNone(undone)
        self.assertEqual(stack.undo_depth, 0)
        stack.push_redo(undone)
        self.assertEqual(stack.redo_depth, 1)


class SemanticLensTests(unittest.TestCase):
    def test_amd64_syscall_lens_marks_r10_and_number(self) -> None:
        rows = syscall_lens("openat", "amd64")
        by_register = {row.register: row for row in rows}
        self.assertEqual(by_register["RAX"].value_hint, "SYS_openat = 257")
        self.assertIn("R10", by_register)
        self.assertIn("不是 RCX", by_register["R10"].meaning_zh)
        self.assertIn("rsi", by_register["RSI"].meaning_zh)

    def test_i386_call_lens_uses_stack_arguments(self) -> None:
        rows = call_lens("i386")
        self.assertTrue(any(row.register == "栈" for row in rows))
        self.assertTrue(any(row.role == "retval" and row.register == "EAX" for row in rows))

    def test_render_is_stable_and_arch_aware(self) -> None:
        text = render_lens(syscall_lens("read", "aarch64"), "Syscall Lens · aarch64")
        self.assertIn("SYS_read = 63", text)
        self.assertIn("X8", text)
        self.assertIn("X0", text)


if __name__ == "__main__":
    unittest.main()
