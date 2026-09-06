from __future__ import annotations

import unittest

from pwnbao.features.heapviz.bridge_session import HeapSession


SOURCE = """
def add(size, data):
    pass

add(0x18, b'A')
add(0x38, b'B')
"""


class HeapSessionAddressTruthTests(unittest.TestCase):
    def test_default_source_keeps_symbolic_heap_base_and_offsets(self) -> None:
        state = HeapSession().load(source=SOURCE)

        self.assertFalse(state["heap_base_specified"])
        self.assertNotIn("heap_base", state["variables"])
        final = state["steps"][-1]
        chunks = final["chunks"]
        self.assertEqual(chunks[0]["address"], "heap_base+0x290")
        self.assertEqual(chunks[0]["heap_offset"], "0x290")
        self.assertEqual(chunks[1]["address"], "heap_base+0x2b0")
        self.assertEqual(chunks[1]["heap_offset"], "0x2b0")

    def test_explicit_source_heap_base_allows_absolute_addresses(self) -> None:
        state = HeapSession().load(source="heap_base = 0x555555559000\n" + SOURCE)

        self.assertTrue(state["heap_base_specified"])
        self.assertEqual(state["variables"]["heap_base"], "0x555555559000")
        final = state["steps"][-1]
        self.assertEqual(final["chunks"][0]["address"], "0x555555559290")
        self.assertEqual(final["chunks"][0]["heap_offset"], "0x290")

    def test_removing_source_heap_base_returns_to_symbolic_offsets(self) -> None:
        session = HeapSession()
        session.load(source="heap_base = 0x555555559000\n" + SOURCE)
        state = session.load(source=SOURCE)

        self.assertFalse(state["heap_base_specified"])
        self.assertNotIn("heap_base", state["variables"])
        self.assertEqual(state["steps"][-1]["chunks"][0]["address"], "heap_base+0x290")


if __name__ == "__main__":
    unittest.main()
