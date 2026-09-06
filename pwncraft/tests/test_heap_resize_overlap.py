"""RESIZE_PHYSICAL overlap / rejection contract tests.

修复契约（回归 UnboundLocalError: my_off）：
- 进入任何 resize/overlap 分支前，physical_id 必须唯一解析出
  old_start/old_end/physical_extent，解析不出 → 结构化拒绝；
- new_start/new_end 统一先算，overlap 判定统一做
  [new_start,new_end) ∩ [other_start,other_end)，不挑"最近邻居"；
- 事务异常必须整体回滚并转成 {ok:false, reason}，禁止穿透 bridge；
- 覆盖粒度按 word（amd64 0x8 允许半行）。
"""
from __future__ import annotations

import unittest

from pwncraft.electron_bridge import ElectronBridge
from pwncraft.features.heapviz.bridge_session import HeapSession


class ResizeOverlapTests(unittest.TestCase):
    """四 chunk 会话：A/B/C/D 各 0x90 extent，尾步 show 保证 D 可落位。"""

    @classmethod
    def _session(cls) -> HeapSession:
        session = HeapSession()
        for name in ("A", "B", "C", "D"):
            session.append_operation("malloc", chunk=name, request_size="0x88")
        session.append_operation("show", chunk="D")
        return session

    @staticmethod
    def _chunk(step: dict, chunk_id: str) -> dict:
        return next(item for item in step["chunks"] if item["chunk_id"] == chunk_id)

    def _editable_step(self, session: HeapSession) -> int:
        """最后一步不可 resize（没有落位步）；用倒数第二步。"""
        return len(session.state()["steps"]) - 2

    # -- bottom 向下覆盖：半行 0x8 / 整行 0x10 --------------------------

    def test_bottom_overwrite_half_row_0x8(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        b = self._chunk(session.state()["steps"][step], "B")
        c_before = self._chunk(session.state()["steps"][step], "C")

        result = session.structural_edit(
            step, kind="RESIZE_PHYSICAL", chunk_id="B",
            physical_id=b["physical_id"], delta=0x8, edge="bottom",
        )
        after = result["steps"][result["selected_step"]]
        b1 = self._chunk(after, "B")
        c1 = self._chunk(after, "C")

        # 半行覆盖：extent 0x90 → 0x98（word 对齐，允许半行）
        self.assertEqual(int(b1["physical_extent_size"], 0), 0x98)
        # 被覆盖方视图原地不动（真实 overlap，绝不整体挪走）
        self.assertEqual(c1["heap_offset"], c_before["heap_offset"])
        self.assertEqual(int(c1["physical_extent_size"], 0), 0x90)
        codes = [w["code"] for w in after["warnings"]]
        self.assertIn("resize_overlap", codes)

    def test_bottom_overwrite_full_row_0x10(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        b = self._chunk(session.state()["steps"][step], "B")
        result = session.structural_edit(
            step, kind="RESIZE_PHYSICAL", chunk_id="B",
            physical_id=b["physical_id"], delta=0x10, edge="bottom",
        )
        after = result["steps"][result["selected_step"]]
        b1 = self._chunk(after, "B")
        self.assertEqual(int(b1["physical_extent_size"], 0), 0xa0)
        self.assertIn("resize_overlap", [w["code"] for w in after["warnings"]])

    # -- top 向上覆盖：半行 0x8 / 整行 0x10 -----------------------------

    def test_top_overwrite_half_row_0x8(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        b = self._chunk(session.state()["steps"][step], "B")
        result = session.structural_edit(
            step, kind="RESIZE_PHYSICAL", chunk_id="B",
            physical_id=b["physical_id"], delta=-0x8, edge="top",
        )
        after = result["steps"][result["selected_step"]]
        b1 = self._chunk(after, "B")
        # 上边界向上 0x8：start 前移、extent 0x90 → 0x98
        self.assertEqual(int(b1["heap_offset"], 0), int(b["heap_offset"], 0) - 0x8)
        self.assertEqual(int(b1["physical_extent_size"], 0), 0x98)
        self.assertIn("resize_overlap", [w["code"] for w in after["warnings"]])

    def test_top_overwrite_full_row_0x10(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        b = self._chunk(session.state()["steps"][step], "B")
        result = session.structural_edit(
            step, kind="RESIZE_PHYSICAL", chunk_id="B",
            physical_id=b["physical_id"], delta=-0x10, edge="top",
        )
        after = result["steps"][result["selected_step"]]
        b1 = self._chunk(after, "B")
        self.assertEqual(int(b1["heap_offset"], 0), int(b["heap_offset"], 0) - 0x10)
        self.assertEqual(int(b1["physical_extent_size"], 0), 0xa0)
        self.assertIn("resize_overlap", [w["code"] for w in after["warnings"]])

    # -- 收缩：无 overlap 警告，extent 如实缩小 -------------------------

    def test_shrink_bottom_and_top(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        b = self._chunk(session.state()["steps"][step], "B")
        result = session.structural_edit(
            step, kind="RESIZE_PHYSICAL", chunk_id="B",
            physical_id=b["physical_id"], delta=-0x10, edge="bottom",
        )
        after = result["steps"][result["selected_step"]]
        b1 = self._chunk(after, "B")
        self.assertEqual(int(b1["physical_extent_size"], 0), 0x80)
        self.assertNotIn("resize_overlap", [w["code"] for w in after["warnings"]])

        session2 = self._session()
        step2 = self._editable_step(session2)
        b2 = self._chunk(session2.state()["steps"][step2], "B")
        result2 = session2.structural_edit(
            step2, kind="RESIZE_PHYSICAL", chunk_id="B",
            physical_id=b2["physical_id"], delta=0x10, edge="top",
        )
        after2 = result2["steps"][result2["selected_step"]]
        b12 = self._chunk(after2, "B")
        # 上边界向下收：start 后移、extent 缩小、无 overlap
        self.assertEqual(int(b12["heap_offset"], 0), int(b2["heap_offset"], 0) + 0x10)
        self.assertEqual(int(b12["physical_extent_size"], 0), 0x80)
        self.assertNotIn("resize_overlap", [w["code"] for w in after2["warnings"]])

    # -- 无邻居：目标下方只有 top → top 账本同步切分 --------------------

    def test_no_neighbour_grows_into_top(self) -> None:
        session = HeapSession()
        session.append_operation("malloc", chunk="A", request_size="0x88")
        session.append_operation("show", chunk="A")
        step = len(session.state()["steps"]) - 2
        a = self._chunk(session.state()["steps"][step], "A")
        top_before = session.state()["steps"][step]["top"]

        result = session.structural_edit(
            step, kind="RESIZE_PHYSICAL", chunk_id="A",
            physical_id=a["physical_id"], delta=0x10, edge="bottom",
        )
        after = result["steps"][result["selected_step"]]
        a1 = self._chunk(after, "A")
        self.assertEqual(int(a1["physical_extent_size"], 0), 0xa0)
        # top 账本：起点上移 0x10、size 同步缩小
        self.assertEqual(int(after["top"]["size"], 0), int(top_before["size"], 0) - 0x10)
        self.assertNotIn("resize_overlap", [w["code"] for w in after["warnings"]])

    # -- 首 chunk 顶边锁定 ---------------------------------------------

    def test_first_chunk_top_edge_locked(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        a = self._chunk(session.state()["steps"][step], "A")
        with self.assertRaisesRegex(ValueError, "上边界锁定"):
            session.structural_edit(
                step, kind="RESIZE_PHYSICAL", chunk_id="A",
                physical_id=a["physical_id"], delta=-0x10, edge="top",
            )

    # -- 连续覆盖两个 chunk：一次拖动逐一判定，不挑最近邻居 -------------

    def test_continuous_overwrite_of_two_chunks(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        b = self._chunk(session.state()["steps"][step], "B")
        # +0x110：覆盖 C 全部（0x90）+ D 头部（0x80）
        result = session.structural_edit(
            step, kind="RESIZE_PHYSICAL", chunk_id="B",
            physical_id=b["physical_id"], delta=0x110, edge="bottom",
        )
        after = result["steps"][result["selected_step"]]
        b1 = self._chunk(after, "B")
        self.assertEqual(int(b1["physical_extent_size"], 0), 0x1a0)
        self.assertIn("resize_overlap", [w["code"] for w in after["warnings"]])
        # 被覆盖的两个 chunk 视图都原地不动
        for name in ("C", "D"):
            other = self._chunk(after, name)
            self.assertEqual(int(other["physical_extent_size"], 0), 0x90)

    # -- 结构化拒绝：physical_id 解析失败 / 非法 delta，绝不出异常 ------

    def test_unresolvable_physical_id_rejected(self) -> None:
        session = self._session()
        step = self._editable_step(session)
        with self.assertRaisesRegex(ValueError, "唯一解析"):
            session.structural_edit(
                step, kind="RESIZE_PHYSICAL", chunk_id="B",
                physical_id="phys_does_not_exist", delta=0x10, edge="bottom",
            )
        with self.assertRaisesRegex(ValueError, "physical_id"):
            session.structural_edit(
                step, kind="RESIZE_PHYSICAL", chunk_id="B",
                physical_id="", delta=0x10, edge="bottom",
            )

    # -- rpc 层：所有预期非法修改返回 {ok:false, reason}，异常不穿透 ----

    def test_rpc_layer_returns_structured_rejection(self) -> None:
        bridge = ElectronBridge()
        for name in ("A", "B", "C"):
            bridge.rpc_heap_operation({"kind": "malloc", "chunk": name, "request_size": "0x88"})
        bridge.rpc_heap_operation({"kind": "show", "chunk": "C"})

        # 不存在的 physical_id
        result = bridge.rpc_heap_structural_edit({
            "step": 2, "kind": "RESIZE_PHYSICAL", "chunk_id": "B",
            "physical_id": "phys_9999", "delta": "0x10", "edge": "bottom",
        })
        self.assertFalse(result["ok"])
        self.assertIn("唯一解析", result["reason"])

        # 缺 physical_id
        result = bridge.rpc_heap_structural_edit({
            "step": 2, "kind": "RESIZE_PHYSICAL", "chunk_id": "B",
            "delta": "0x10", "edge": "bottom",
        })
        self.assertFalse(result["ok"])
        self.assertIn("physical_id", result["reason"])

        # 非法 delta（非 word 倍数）
        result = bridge.rpc_heap_structural_edit({
            "step": 2, "kind": "RESIZE_PHYSICAL", "chunk_id": "B",
            "physical_id": "phys_0002", "delta": "0x4", "edge": "bottom",
        })
        self.assertFalse(result["ok"])
        self.assertIn("非零倍数", result["reason"])

        # 正常提交 → ok:true + 事务标记 + 映射结构
        ok = bridge.rpc_heap_structural_edit({
            "step": 2, "kind": "RESIZE_PHYSICAL", "chunk_id": "B",
            "physical_id": "phys_0002", "delta": "0x10", "edge": "bottom",
        })
        self.assertTrue(ok["ok"])
        edit = ok["structural_edit"]
        self.assertEqual(edit["kind"], "RESIZE_PHYSICAL")
        self.assertIn("exp_mapping", edit)
        self.assertFalse(edit["exp_mapping"]["safe"])
        self.assertIn("RESIZE_PHYSICAL", edit["canonical_effect"])
        self.assertIn("[0x", edit["canonical_effect"])


if __name__ == "__main__":
    unittest.main()
