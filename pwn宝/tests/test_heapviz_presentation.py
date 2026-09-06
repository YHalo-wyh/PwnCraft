from __future__ import annotations

import unittest

from pwnbao.features.heapviz import GlibcHeapEngine, HeapOperation, HeapOperationKind, build_allocator_config
from pwnbao.features.heapviz.presentation import HeapSceneLayout, build_heap_scene_model, diff_heap_snapshots


class HeapPresentationModelTests(unittest.TestCase):
    def _snapshots(self):
        engine = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35"))
        return engine.replay([
            HeapOperation("op_001", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x68", data="b'A'"),
            HeapOperation("op_002", HeapOperationKind.ALLOC, chunk="B", index="1", request_size="0x68", data="b'B'"),
            HeapOperation("op_003", HeapOperationKind.FREE, chunk="A", index="0"),
        ])

    def test_heap_and_bins_have_independent_fixed_columns(self) -> None:
        snapshots = self._snapshots()
        layout = HeapSceneLayout.for_heap_width(680.0)
        before = build_heap_scene_model(snapshots[2], layout)
        after = build_heap_scene_model(snapshots[3], layout)

        self.assertEqual(before.layout.heap_y, after.layout.heap_y)
        self.assertEqual(before.layout.bin_y, after.layout.bin_y)
        self.assertGreater(after.layout.bin_x, after.layout.heap_x + after.layout.heap_width)
        self.assertFalse(before.bin_rows)
        self.assertTrue(after.bin_rows)
        self.assertEqual([group.chunks[0].chunk_id for group in after.groups], ["A", "B"])

    def test_snapshot_diff_uses_physical_identity_and_bin_edges(self) -> None:
        snapshots = self._snapshots()
        created = diff_heap_snapshots(snapshots[0], snapshots[1])
        freed = diff_heap_snapshots(snapshots[2], snapshots[3])

        self.assertTrue(any(item.action == "create" and item.kind == "chunk" for item in created))
        self.assertTrue(any(item.action == "update" and item.kind == "chunk" for item in freed))
        self.assertTrue(any(item.action == "create" and item.kind == "bin_edge" for item in freed))


if __name__ == "__main__":
    unittest.main()
