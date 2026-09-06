from __future__ import annotations

import unittest
from dataclasses import replace

from pwncraft.features.heapviz import (
    ChunkMemoryView,
    GlibcHeapEngine,
    HeapOperation,
    HeapOperationKind,
    MemoryProvenance,
    MemoryAddress,
    PayloadEvaluator,
    PhysicalMemory,
    ProvenanceKind,
    analyze_heap_source,
    build_allocator_config,
)
from pwncraft.features.heapviz.allocators.bin_transitions import insert_doubly, remove_doubly
from pwncraft.features.heapviz.benchmark import SemanticBenchmarkRunner, default_benchmark_path
from pwncraft.features.heapviz.presentation.scene_model import build_heap_scene_model


class PhysicalMemoryKernelTests(unittest.TestCase):
    def test_doubly_chain_transition_mutates_only_required_links(self) -> None:
        inserted = insert_doubly(["A", "B"], "C", at_head=True)
        self.assertEqual(inserted.after, ("C", "A", "B"))
        self.assertEqual(
            {(item.node, item.field, item.target) for item in inserted.mutations},
            {
                ("C", "fd", "A"),
                ("C", "bk", "main_arena"),
                ("main_arena", "fd", "C"),
                ("A", "bk", "C"),
            },
        )
        removed = remove_doubly(inserted.after, "A")
        self.assertEqual(removed.after, ("C", "B"))
        self.assertEqual(
            {(item.node, item.field, item.target) for item in removed.mutations},
            {("C", "fd", "B"), ("B", "bk", "C")},
        )

    def test_fastbin_malloc_refills_tcache_from_physical_chain(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations = [
            HeapOperation(f"a{i}", HeapOperationKind.ALLOC, chunk=f"A{i}", index=str(i), request_size="0x20")
            for i in range(9)
        ]
        operations.extend(
            HeapOperation(f"f{i}", HeapOperationKind.FREE, chunk=f"A{i}", index=str(i))
            for i in range(9)
        )
        operations.extend(
            HeapOperation(f"d{i}", HeapOperationKind.ALLOC, chunk=f"D{i}", index=str(20 + i), request_size="0x20")
            for i in range(7)
        )
        operations.append(HeapOperation("take", HeapOperationKind.ALLOC, chunk="take", index="40", request_size="0x20"))
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        self.assertEqual(snapshot.chunks["take"].address, snapshot.chunks["A8"].address)
        self.assertEqual(snapshot.bins.fastbins, {})
        self.assertEqual(snapshot.bins.tcache["0x30"], ("A7",))
        self.assertEqual(snapshot.chunks["A7"].view_kind, "tcache_entry")
        self.assertTrue(any(event.action == "refill" and event.moved_nodes == ("A7",) for event in snapshot.bin_transition_events))
        self.assertIn("tcache refill(1)", snapshot.alloc_events[0].source)

    def test_smallbin_tail_malloc_refills_tcache_and_preserves_order(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.35")
        operations: list[HeapOperation] = []
        for i in range(7):
            operations.append(HeapOperation(f"pad{i}", HeapOperationKind.ALLOC, chunk=f"P{i}", index=str(i), request_size="0xf0"))
        for i in range(3):
            operations.append(HeapOperation(f"s{i}", HeapOperationKind.ALLOC, chunk=f"S{i}", index=str(10 + i * 2), request_size="0xf0"))
            operations.append(HeapOperation(f"g{i}", HeapOperationKind.ALLOC, chunk=f"G{i}", index=str(11 + i * 2), request_size="0x20"))
        operations.extend(HeapOperation(f"fp{i}", HeapOperationKind.FREE, chunk=f"P{i}", index=str(i)) for i in range(7))
        operations.extend(HeapOperation(f"fs{i}", HeapOperationKind.FREE, chunk=f"S{i}", index=str(10 + i * 2)) for i in range(3))
        operations.append(HeapOperation("sort", HeapOperationKind.ALLOC, chunk="sort", index="30", request_size="0x200"))
        operations.extend(
            HeapOperation(f"drain{i}", HeapOperationKind.ALLOC, chunk=f"D{i}", index=str(40 + i), request_size="0xf0")
            for i in range(7)
        )
        operations.append(HeapOperation("take", HeapOperationKind.ALLOC, chunk="take", index="60", request_size="0xf0"))
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        self.assertEqual(snapshot.chunks["take"].address, snapshot.chunks["S0"].address)
        self.assertEqual(snapshot.bins.smallbins, {})
        self.assertEqual(snapshot.bins.tcache["0x100"], ("S2", "S1"))
        refill = [event for event in snapshot.bin_transition_events if event.action == "refill"]
        self.assertEqual(refill[-1].moved_nodes, ("S1", "S2"))
        self.assertIn("smallbin", refill[-1].bin_kind)

    def test_doubly_refresh_does_not_erase_program_corruption(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.23")
        operations = [
            HeapOperation("a", HeapOperationKind.ALLOC, chunk="A", index="0", request_size="0x100"),
            HeapOperation("ga", HeapOperationKind.ALLOC, chunk="GA", index="1", request_size="0x20"),
            HeapOperation("b", HeapOperationKind.ALLOC, chunk="B", index="2", request_size="0x100"),
            HeapOperation("gb", HeapOperationKind.ALLOC, chunk="GB", index="3", request_size="0x20"),
            HeapOperation("fa", HeapOperationKind.FREE, chunk="A", index="0"),
            HeapOperation("fb", HeapOperationKind.FREE, chunk="B", index="2"),
            HeapOperation("sort", HeapOperationKind.ALLOC, chunk="sort", index="4", request_size="0x300"),
            HeapOperation("corrupt", HeapOperationKind.EDIT, chunk="A", index="0", data="p64(0x4141414142424242)"),
            HeapOperation("refresh", HeapOperationKind.ALLOC, chunk="other", index="5", request_size="0x350"),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        fd = next(field for field in snapshot.chunks["A"].fields if field.name == "fd")
        self.assertEqual(fd.value, "0x4141414142424242")

    def test_largebin_size_representatives_have_nextsize_ring(self) -> None:
        config = build_allocator_config("amd64", "glibc 2.23")
        operations = [
            HeapOperation("l1", HeapOperationKind.ALLOC, chunk="L1", index="0", request_size="0x500"),
            HeapOperation("g1", HeapOperationKind.ALLOC, chunk="G1", index="1", request_size="0x20"),
            HeapOperation("l2", HeapOperationKind.ALLOC, chunk="L2", index="2", request_size="0x600"),
            HeapOperation("g2", HeapOperationKind.ALLOC, chunk="G2", index="3", request_size="0x20"),
            HeapOperation("f1", HeapOperationKind.FREE, chunk="L1", index="0"),
            HeapOperation("f2", HeapOperationKind.FREE, chunk="L2", index="2"),
            HeapOperation("sort", HeapOperationKind.ALLOC, chunk="sort", index="4", request_size="0x700"),
        ]
        snapshot = GlibcHeapEngine(config).replay(operations)[-1]
        for left, right in (("L1", "L2"), ("L2", "L1")):
            fields = {field.name: field.value for field in snapshot.chunks[left].fields}
            self.assertEqual(fields["fd_nextsize"], snapshot.chunks[right].address)
            self.assertEqual(fields["bk_nextsize"], snapshot.chunks[right].address)

    def test_sparse_write_splits_spans_and_preserves_provenance(self) -> None:
        memory = PhysicalMemory()
        first = MemoryProvenance.derived("op_1", writer="allocator")
        second = MemoryProvenance(ProvenanceKind.DERIVED, "op_2", 7, "p16(0x4242)", 3, "A")
        memory.write("heap_base+0x100", b"ABCDEFGH", first)
        memory.write("heap_base+0x103", b"BB", second)
        self.assertEqual(memory.read("heap_base+0x100", 8).data, b"ABCBBFGH")
        self.assertEqual(memory.read("heap_base+0x103", 2).provenance, (second,))
        self.assertEqual(len(memory.spans), 3)

    def test_symbolic_address_spaces_do_not_alias(self) -> None:
        memory = PhysicalMemory()
        provenance = MemoryProvenance.derived("op")
        memory.write("heap_base+0x20", b"A", provenance)
        memory.write("libc_base+0x20", b"B", provenance)
        self.assertEqual(memory.read("heap_base+0x20", 1).data, b"A")
        self.assertEqual(memory.read("libc_base+0x20", 1).data, b"B")

    def test_payload_ir_supports_pack_repeat_flat_fit_and_struct(self) -> None:
        evaluator = PayloadEvaluator(bits=64, variables={"target": 0x404040})
        payload = evaluator.evaluate("b'A'*8 + p16(0x4243) + (0x11223344).to_bytes(4, 'big')")
        self.assertEqual(payload.length, 14)
        self.assertEqual(payload.materialize(), b"A" * 8 + b"CB" + b"\x11\x22\x33\x44")
        sparse = evaluator.evaluate("flat({0x10: 0x91, 0x18: target}, filler=b'Z')")
        self.assertEqual([(item.offset, item.length) for item in sparse.segments], [(0, 16), (16, 8), (24, 8)])
        self.assertEqual(sparse.materialize(), b"Z" * 16 + (0x91).to_bytes(8, "little") + (0x404040).to_bytes(8, "little"))
        packed = evaluator.evaluate("struct.pack('<IQ', 0x41, target)")
        self.assertEqual(packed.length, 12)

    def test_overflow_physically_changes_adjacent_metadata_and_records_cause(self) -> None:
        source = "add(0x20,b'A')\nadd(0x20,b'B')\npayload=b'A'*0x28+p64(0x51)\nedit(0,payload)\n"
        analysis = analyze_heap_source(source)
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(analysis.operations)[-1]
        self.assertEqual(snapshot.memory.read_uint("heap_base+0x2c8", 8), 0x51)
        self.assertEqual(snapshot.chunks["B"].chunk_size, "0x50")
        edge = next(item for item in snapshot.overwrite_edges if item.target_chunk == "B" and item.target_field == "size")
        self.assertEqual((edge.source_payload_offset, edge.before, edge.after), (0x28, "0x31", "0x51"))
        self.assertEqual(snapshot.write_events[0].source_line, 4)

    def test_off_by_one_changes_only_one_size_byte(self) -> None:
        source = "add(0x20,b'A')\nadd(0x80,b'B')\nedit(0,b'A'*0x28+b'\\x00')\n"
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(analyze_heap_source(source).operations)[-1]
        edge = next(item for item in snapshot.overwrite_edges if item.target_chunk == "B" and item.target_field == "size")
        start, end = MemoryAddress.parse(edge.physical_start), MemoryAddress.parse(edge.physical_end)
        self.assertEqual(start.distance_to(end), 1)
        self.assertEqual(edge.source_payload_offset, 0x28)
        self.assertEqual(snapshot.memory.read_uint("heap_base+0x2c8", 8), 0)

    def test_tcache_poison_uses_freelist_head_not_pending_side_channel(self) -> None:
        source = "add(0x20,b'A')\ndelete(0)\nedit(0,p64(0x404040))\nadd(0x20,b'B')\nadd(0x20,b'C')\n"
        engine = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.31"))
        snapshots = engine.replay(analyze_heap_source(source).operations)
        self.assertFalse(hasattr(engine, "_pending_target_by_size"))
        self.assertEqual(snapshots[-1].chunks["C"].user_address, "0x404040")
        self.assertIn("external @ 0x404040", snapshots[-2].bins.tcache["0x30"])

    def test_safe_link_view_exposes_stored_and_decoded(self) -> None:
        config = replace(build_allocator_config("amd64", "glibc 2.35"), heap_base="0x555555559000")
        source = "add(0x20,b'A')\ndelete(0)\nedit(0,p64(0x404040 ^ (0x5555555592a0 >> 12)))\n"
        snapshot = GlibcHeapEngine(config).replay(analyze_heap_source(source).operations)[-1]
        view = ChunkMemoryView(snapshot.memory, snapshot.chunks["A"].address, bits=64, lifecycle="freed", bin_location="tcache[0x30]", safe_linking=True)
        next_field = next(item for item in view.fields() if item.name == "next")
        self.assertTrue(next_field.stored_value.startswith("0x"))
        self.assertEqual(next_field.decoded_value, "0x404040")

    def test_regular_free_writes_real_boundary_tag_but_tcache_free_does_not(self) -> None:
        regular = replace(build_allocator_config("amd64", "glibc 2.35"), tcache_enabled=False, max_fast_chunk_size=0)
        source = "add(0x100,b'A')\nadd(0x100,b'B')\ndelete(0)\n"
        snapshot = GlibcHeapEngine(regular).replay(analyze_heap_source(source).operations)[-1]
        b = snapshot.chunks["B"]
        self.assertEqual(b.fields[0].value, "0x110")
        self.assertIn("PREV_INUSE=0", b.fields[1].value)

        tcache = GlibcHeapEngine(build_allocator_config("amd64", "glibc 2.35")).replay(
            analyze_heap_source("add(0x20,b'A')\nadd(0x20,b'B')\ndelete(0)\n").operations
        )[-1]
        # malloc has initialized the physical boundary word; tcache free does
        # not publish a new footer or clear PREV_INUSE.
        self.assertEqual(tcache.chunks["B"].fields[0].value, "0x30")
        self.assertIn("PREV_INUSE=1", tcache.chunks["B"].fields[1].value)

    def test_overlapping_views_share_one_physical_memory(self) -> None:
        source = "add(0x20,b'A')\nadd(0x20,b'B')\nedit(0,b'A'*0x28+p64(0x61))\ndelete(1)\nadd(0x50,b'C')\nadd(0x20,b'D')\n"
        snapshot = GlibcHeapEngine(build_allocator_config()).replay(analyze_heap_source(source).operations)[-1]
        model = build_heap_scene_model(snapshot)
        group = next(item for item in model.groups if {chunk.chunk_id for chunk in item.chunks} >= {"C", "D"})
        self.assertTrue(group.overlap)
        self.assertTrue(group.shared_memory)
        self.assertIs(snapshot.chunks["C"].memory_regions[0].__class__, snapshot.chunks["D"].memory_regions[0].__class__)

    def test_ground_truth_benchmark_covers_v010_required_scenarios(self) -> None:
        report = SemanticBenchmarkRunner().run_file(default_benchmark_path())
        self.assertGreaterEqual(len(report.cases), 50)
        self.assertEqual(report.whole_case_pass_rate, 1.0, report.to_dict())
        self.assertTrue(all(value == 1.0 for value in report.metrics.values()), report.to_dict())


if __name__ == "__main__":
    unittest.main()
