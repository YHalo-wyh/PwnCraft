from __future__ import annotations

import unittest

from pwnbao.features.heapviz.bridge_session import HeapSession


SOURCE = """
def add(size, index):
    pass

def delete(index):
    pass

for i in range(8):
    add(0x100, i)

for i in range(1, 8):
    delete(i)
delete(0)

for i in range(1, 8):
    add(0x100, i)
"""


class TcacheIdentityTruthTests(unittest.TestCase):
    def test_tcache_lifo_and_physical_identity_are_one_authoritative_flow(self) -> None:
        state = HeapSession().load(source=SOURCE)
        steps = state["steps"]
        expected_heads = [
            ["H", "G", "F", "E", "D", "C", "B"],
            ["G", "F", "E", "D", "C", "B"],
            ["F", "E", "D", "C", "B"],
            ["E", "D", "C", "B"],
            ["D", "C", "B"],
            ["C", "B"],
            ["B"],
            [],
        ]
        expected_allocations = ["I", "J", "K", "L", "M", "N", "O"]
        expected_physical = [
            "phys_0008", "phys_0007", "phys_0006", "phys_0005",
            "phys_0004", "phys_0003", "phys_0002",
        ]

        for offset, expected_chain in enumerate(expected_heads):
            step = steps[16 + offset]
            self.assertEqual(step["bins"]["tcache"].get("0x110", []), expected_chain)
            physical_ids = [item["physical_id"] for item in step["physical_chunks"]]
            self.assertEqual(len(physical_ids), len(set(physical_ids)))
            self.assertEqual(len(physical_ids), 8)

        for offset, (chunk_id, physical_id) in enumerate(zip(expected_allocations, expected_physical), 1):
            step = steps[16 + offset]
            current = next(item for item in step["physical_chunks"] if item["physical_id"] == physical_id)
            self.assertEqual(current["chunk_id"], chunk_id)
            self.assertEqual(current["lifecycle"], "allocated")
            self.assertEqual(current["allocation_generation"], 2)

        final = steps[23]
        self.assertEqual(
            [item["chunk_id"] for item in final["physical_chunks"]],
            ["A", "O", "N", "M", "L", "K", "J", "I"],
        )
        # Historical TypedViews remain available, but cannot become extra
        # physical Canvas cards.
        self.assertGreater(len(final["typed_views"]), len(final["physical_chunks"]))

    def test_tcache_head_is_materialized_in_physical_memory(self) -> None:
        session = HeapSession()
        session.load(source=SOURCE)
        objects = session.snapshots[16].memory.objects
        head = next(item for item in objects if item.object_id == "tcache_head:0x110")
        self.assertEqual(head.kind, "tcache_perthread_entry")
        self.assertEqual(head.start.root, "tcache_entries_110")


if __name__ == "__main__":
    unittest.main()
