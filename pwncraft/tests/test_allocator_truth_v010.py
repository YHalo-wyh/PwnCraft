from __future__ import annotations

import unittest
from dataclasses import replace

from pwncraft.features.heapviz.allocators.profiles import build_allocator_config
from pwncraft.features.heapviz.analyzer import analyze_heap_source
from pwncraft.features.heapviz.engine import GlibcHeapEngine
from pwncraft.features.heapviz.events import WriteImpactKind
from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind
from pwncraft.features.heapviz.views import TopChunkView


class AllocatorTruthClosureTests(unittest.TestCase):
    @staticmethod
    def _regular_config():
        return replace(
            build_allocator_config("amd64", "glibc 2.35"),
            tcache_enabled=False,
            max_fast_chunk_size=0,
        )

    def test_prev_inuse_one_blocks_backward_consolidation(self) -> None:
        source = """
add(0x500, b'A')
add(0x500, b'B')
add(0x20, b'C')
delete(0)
edit(0, b'X' * 0x508 + p64(0x511))
delete(1)
"""
        snapshot = GlibcHeapEngine(self._regular_config()).replay(analyze_heap_source(source).operations)[-1]
        self.assertIn("PREV_INUSE=1", snapshot.chunks["B"].fields[1].value)
        self.assertEqual(snapshot.chunks["A"].lifecycle, "freed")
        self.assertEqual(snapshot.chunks["B"].lifecycle, "freed")
        self.assertNotIn("merged into", snapshot.chunks["B"].bin_location)

    def test_prev_size_and_prev_inuse_drive_normal_backward_consolidation(self) -> None:
        source = "add(0x500,b'A')\nadd(0x500,b'B')\nadd(0x20,b'C')\ndelete(0)\ndelete(1)\n"
        snapshot = GlibcHeapEngine(self._regular_config()).replay(analyze_heap_source(source).operations)[-1]
        self.assertEqual(snapshot.chunks["A"].chunk_size, "0xa20")
        self.assertEqual(snapshot.chunks["B"].lifecycle, "stale")
        self.assertEqual(snapshot.chunks["B"].bin_location, "merged into A")

    def test_tcache_duplicate_reads_key_and_traverses_memory(self) -> None:
        normal = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35")).replay(
            analyze_heap_source("add(0x20,b'A')\ndelete(0)\ndelete(0)\n").operations
        )[-1]
        self.assertEqual(normal.allocator_abort.reason, "tcache_double_free_abort")
        self.assertEqual(normal.allocator_abort.metadata["key_match"], "true")

        bypass = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35")).replay(
            analyze_heap_source("add(0x20,b'A')\ndelete(0)\nedit(0,p64(0)+p64(0))\ndelete(0)\n").operations
        )[-1]
        self.assertIsNone(bypass.allocator_abort)
        self.assertEqual(bypass.bins.tcache["0x30"], ("A", "A"))

    def test_top_overwrite_is_an_impact_and_drives_next_malloc(self) -> None:
        snapshots = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35")).replay(
            analyze_heap_source("add(0x20,b'A')\nedit(0,b'X'*0x28+p64(0x1001))\nadd(0x100,b'B')\n").operations
        )
        overwrite = snapshots[2]
        impacts = [impact for event in overwrite.write_events for impact in event.affected_regions]
        self.assertTrue(any(item.target_chunk == "top" and item.target_field == "prev_size" for item in impacts))
        top_size = next(item for item in impacts if item.target_chunk == "top" and item.target_field == "size")
        self.assertEqual(top_size.kind, WriteImpactKind.TOP_METADATA_CORRUPTION.value)
        self.assertEqual(top_size.before, "0x20d41")
        self.assertEqual(top_size.after, "0x1001")
        self.assertEqual(overwrite.top_size, "0x1000")
        self.assertEqual(snapshots[3].chunks["B"].address, "heap_base+0x2c0")
        self.assertEqual(snapshots[3].top_size, "0xef0")

    def test_top_typed_view_reads_same_memory(self) -> None:
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(
            analyze_heap_source("add(0x20,b'A')\nedit(0,b'X'*0x28+p64(0x1001))\n").operations
        )[-1]
        view = TopChunkView(snapshot.memory, snapshot.top_address)
        fields = {field.name: field.value for field in view.fields()}
        self.assertEqual(fields["size"], "0x1001")
        self.assertEqual(fields["end"], "heap_base+0x12c0")

    def test_partial_size_overwrite_records_field_byte_range_and_mask(self) -> None:
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(
            analyze_heap_source("add(0x20,b'A')\nadd(0x20,b'B')\nedit(0,b'A'*0x28+b'\\x00')\n").operations
        )[-1]
        impacts = [impact for event in snapshot.write_events for impact in event.affected_regions]
        impact = next(item for item in impacts if item.target_chunk == "B" and item.target_field == "size")
        self.assertEqual(impact.target_field_offset, 0)
        self.assertEqual(impact.target_field_length, 1)
        self.assertEqual(impact.source_payload_offset, 0x28)
        self.assertEqual(impact.source_payload_length, 1)
        self.assertEqual(impact.kind, WriteImpactKind.PARTIAL_FIELD_OVERWRITE.value)
        self.assertEqual(impact.changed_byte_mask, "ff 00 00 00 00 00 00 00")

    def test_unsorted_corruption_is_consumed_as_integrity_abort(self) -> None:
        source = "add(0x500,b'A')\nadd(0x20,b'G')\ndelete(0)\nedit(0,p64(0)+p64(0))\nadd(0x400,b'B')\n"
        snapshot = GlibcHeapEngine(self._regular_config()).replay(analyze_heap_source(source).operations)[-1]
        self.assertEqual(snapshot.allocator_abort.reason, "corrupted_double_linked_list")
        self.assertIn("victim->fd->bk", snapshot.allocator_abort.check)
        self.assertEqual(snapshot.alloc_events, ())
        self.assertEqual(len(snapshot.chunks), 2)

    def test_fake_evidence_candidate_then_allocator_confirmed(self) -> None:
        result = analyze_heap_source("layout = flat(0, 0x91, fd, bk)\n")
        fake_operations = [item for item in result.operations if item.kind == HeapOperationKind.FAKE_CHUNK]
        self.assertEqual(len(fake_operations), 1)
        self.assertEqual(fake_operations[0].meta["evidence_level"], "candidate")
        operations = [
            fake_operations[0],
            HeapOperation("op_free", HeapOperationKind.FREE, chunk="layout"),
        ]
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(operations)[-1]
        self.assertEqual(snapshot.chunks["layout"].evidence_level, "confirmed")

    def test_fake_candidate_pointer_storage_promotes_to_likely(self) -> None:
        fake = next(
            item for item in analyze_heap_source("layout = flat(0, 0x91, fd, bk)\n").operations
            if item.kind == HeapOperationKind.FAKE_CHUNK
        )
        operations = [
            fake,
            HeapOperation("op_alloc", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x20"),
            HeapOperation("op_edit", HeapOperationKind.EDIT, chunk="A", index="0", data="p64(layout)"),
        ]
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(operations)[-1]
        self.assertEqual(snapshot.chunks["layout"].evidence_level, "likely")

    def test_rop_words_are_not_fake_chunk_evidence(self) -> None:
        result = analyze_heap_source("payload = flat(pop_rdi, bin_sh, ret, system)\n")
        self.assertFalse(any(item.kind == HeapOperationKind.FAKE_CHUNK for item in result.operations))

    def test_cache_divergence_detected_without_repair(self) -> None:
        engine = GlibcHeapEngine(build_allocator_config())
        engine.replay(analyze_heap_source("add(0x20,b'A')\ndelete(0)\nedit(0,p64(0x41414141))\n").operations)
        with self.assertRaisesRegex(AssertionError, "diverged"):
            engine.assert_cache_consistency()
        raw = engine.physical_memory.read("heap_base+0x2a0", 8).data
        self.assertEqual(int.from_bytes(raw, "little"), 0x41414141)


if __name__ == "__main__":
    unittest.main()
