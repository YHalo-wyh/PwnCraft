from __future__ import annotations

import unittest

from pwncraft.features.heapviz.bridge_session import HeapSession


SOURCE = """
def add(size, data):
    pass

def delete(index):
    pass

add(0x18, b'A')
add(0x28, b'B')
add(0x38, b'C')
"""


class HeapStructuralEditTests(unittest.TestCase):
    @staticmethod
    def _chunk(step: dict, chunk_id: str) -> dict:
        return next(item for item in step["chunks"] if item["chunk_id"] == chunk_id)

    def test_append_user_row_rebuilds_successor_offsets_and_top_atomically(self) -> None:
        session = HeapSession()
        before_state = session.load(template_id="basic_heap_layout")
        selected_step = len(before_state["steps"]) - 1
        before = before_state["steps"][selected_step]
        a0 = self._chunk(before, "A")
        b0 = self._chunk(before, "B")
        c0 = self._chunk(before, "C")
        top0 = int(before["top"]["address"].split("+")[-1], 0)

        after_state = session.structural_edit(
            selected_step, kind="APPEND_USER_ROW", chunk_id="A",
            physical_id=a0["physical_id"], delta=0x10,
        )
        after = after_state["steps"][selected_step]
        a1 = self._chunk(after, "A")
        b1 = self._chunk(after, "B")
        c1 = self._chunk(after, "C")
        top1 = int(after["top"]["address"].split("+")[-1], 0)

        self.assertEqual(int(a1["chunk_size"], 0), int(a0["chunk_size"], 0) + 0x10)
        self.assertEqual(int(b1["heap_offset"], 0), int(b0["heap_offset"], 0) + 0x10)
        self.assertEqual(int(c1["heap_offset"], 0), int(c0["heap_offset"], 0) + 0x10)
        self.assertEqual(top1, top0 + 0x10)
        self.assertEqual(int(after["top"]["size"], 0), int(before["top"]["size"], 0) - 0x10)
        self.assertEqual(after_state["structural_edit"]["kind"], "APPEND_USER_ROW")
        self.assertEqual(after_state["selected_step"], selected_step)

    def test_structural_edit_survives_source_reanalysis_without_becoming_a_write(self) -> None:
        session = HeapSession()
        before_state = session.load(source=SOURCE)
        selected_step = len(before_state["steps"]) - 1
        a0 = self._chunk(before_state["steps"][selected_step], "A")
        edited = session.structural_edit(
            selected_step, kind="APPEND_USER_ROW", chunk_id="A",
            physical_id=a0["physical_id"], delta=0x10,
        )
        size_after_edit = int(self._chunk(edited["steps"][selected_step], "A")["chunk_size"], 0)

        replayed = session.load(source=SOURCE)
        self.assertEqual(
            int(self._chunk(replayed["steps"][selected_step], "A")["chunk_size"], 0),
            size_after_edit,
        )
        self.assertEqual(replayed["structural_edits"][0]["kind"], "APPEND_USER_ROW")
        self.assertFalse(replayed["steps"][selected_step]["overwrite_edges"])

    def test_rejects_non_row_delta(self) -> None:
        session = HeapSession()
        state = session.load(template_id="basic_heap_layout")
        step = len(state["steps"]) - 1
        a = self._chunk(state["steps"][step], "A")
        with self.assertRaisesRegex(ValueError, "0x10"):
            session.structural_edit(
                step, kind="APPEND_USER_ROW", chunk_id="A",
                physical_id=a["physical_id"], delta=8,
            )

    # -- INSERT_USER_ROW：任意行下方插入真实物理行（≠ 尾部追加，≠ 边界拖动）

    def test_insert_user_row_shifts_tail_bytes_and_successors(self) -> None:
        session = HeapSession()
        state = session.load(template_id="basic_heap_layout")
        step = len(state["steps"]) - 1
        b0 = self._chunk(state["steps"][step], "B")
        c0 = self._chunk(state["steps"][step], "C")
        top0 = int(state["steps"][step]["top"]["address"].split("+")[-1], 0)

        after_state = session.structural_edit(
            step, kind="INSERT_USER_ROW", chunk_id="B",
            physical_id=b0["physical_id"], delta=0x10,
            data_hex="41" * 8 + "42" * 8, after_user_offset=0x10,
        )
        after = after_state["steps"][step]
        b1 = self._chunk(after, "B")
        c1 = self._chunk(after, "C")

        self.assertEqual(int(b1["chunk_size"], 0), int(b0["chunk_size"], 0) + 0x10)
        self.assertEqual(int(c1["heap_offset"], 0), int(c0["heap_offset"], 0) + 0x10)
        # 新行字节落在 user+0x10 / user+0x18（chunk 相对 0x20 / 0x28）
        regions = {(r["start"], r["end"]): r["value"] for r in b1["regions"]}
        self.assertEqual(regions[(32, 40)], "b'AAAAAAAA'")
        self.assertEqual(regions[(40, 48)], "b'BBBBBBBB'")
        # 原有字节保持在原位
        self.assertEqual(regions[(16, 24)], "b'BBBBBBBB'")
        # top 账本随重放重算
        self.assertEqual(
            int(after["top"]["address"].split("+")[-1], 0), top0 + 0x10,
        )
        self.assertEqual(after_state["structural_edit"]["kind"], "INSERT_USER_ROW")
        self.assertEqual(after_state["structural_edit"]["exp_status"], "pending")
        # 统一映射结构：safe=False 时绝不编造 EXP，只保留物理修正 + 学习
        self.assertFalse(after_state["structural_edit"]["exp_mapping"]["safe"])
        self.assertIn("INSERT_USER_ROW", after_state["structural_edit"]["canonical_effect"])
        self.assertTrue(after_state["learning"]["learned_rules_added"])

    def test_insert_user_row_survives_source_reanalysis(self) -> None:
        source = "\n".join([
            "def add(size, data):",
            "    pass",
            "",
            "add(0x18, b'A')",
            "add(0x38, b'B')",
            "add(0x58, b'C')",
        ])
        session = HeapSession()
        state = session.load(source=source)
        step = len(state["steps"]) - 1
        b = self._chunk(state["steps"][step], "B")
        session.structural_edit(
            step, kind="INSERT_USER_ROW", chunk_id="B",
            physical_id=b["physical_id"], delta=0x10,
            data_hex="41" * 8 + "42" * 8, after_user_offset=0x10,
        )
        replayed = session.load(source=source)
        b1 = self._chunk(replayed["steps"][step], "B")
        self.assertEqual(int(b1["chunk_size"], 0), int(b["chunk_size"], 0) + 0x10)
        regions = {(r["start"], r["end"]): r["value"] for r in b1["regions"]}
        self.assertEqual(regions[(32, 40)], "b'AAAAAAAA'")

    def test_insert_user_row_rejections(self) -> None:
        session = HeapSession()
        state = session.load(template_id="basic_heap_layout")
        step = len(state["steps"]) - 1
        b = self._chunk(state["steps"][step], "B")
        # 中插留空：新物理字节没有旧值可保留，必须硬拒绝而不是补 0
        with self.assertRaisesRegex(ValueError, "完整行字节"):
            session.structural_edit(
                step, kind="INSERT_USER_ROW", chunk_id="B",
                physical_id=b["physical_id"], delta=0x10,
                data_hex="", after_user_offset=0x10,
            )
        # 插入位置未按整行对齐
        with self.assertRaisesRegex(ValueError, "对齐"):
            session.structural_edit(
                step, kind="INSERT_USER_ROW", chunk_id="B",
                physical_id=b["physical_id"], delta=0x10,
                data_hex="41" * 16, after_user_offset=0x8,
            )
        # 插入位置越界
        with self.assertRaisesRegex(ValueError, "超出 user 区"):
            session.structural_edit(
                step, kind="INSERT_USER_ROW", chunk_id="B",
                physical_id=b["physical_id"], delta=0x10,
                data_hex="41" * 16, after_user_offset=0x999,
            )
        # 非整行 delta
        with self.assertRaisesRegex(ValueError, "0x10"):
            session.structural_edit(
                step, kind="INSERT_USER_ROW", chunk_id="B",
                physical_id=b["physical_id"], delta=8,
                data_hex="41" * 8, after_user_offset=0x0,
            )


if __name__ == "__main__":
    unittest.main()
