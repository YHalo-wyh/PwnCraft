"""v0.29 tests: Electron bridge v2 — heap replay, corrections + learning,
IOFILE, fmt/cyclic/convert, and the offline halves of the debug launch.

The Electron renderer only animates what this bridge emits, so these tests
pin the JSON contract of every new RPC family that runs offline.  WSL-only
endpoints (cli_run, pwndbg install) are covered by their own suites and are
excluded here.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TCACHE_CHAIN_SOURCE = """
def add(size, data):
    pass

def delete(index):
    pass

add(0x68, b'A')
add(0x68, b'B')
delete(0)
delete(1)
"""


class ElectronBridgeV2Tests(unittest.TestCase):
    def _run_bridge(self, requests: list[dict]) -> list[dict]:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "pwncraft.electron_bridge"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            cwd=str(PROJECT_ROOT),
        )
        payload = "\n".join(json.dumps(request) for request in requests)
        out, err = proc.communicate(payload, timeout=180)
        if err.strip():
            self.fail(f"bridge stderr 非空: {err[:300]}")
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def _rpc(self, messages: list[dict], request_id: int) -> dict:
        return next(m for m in messages if m.get("id") == request_id)

    # ------------------------------------------------------------------
    # heap replay

    def test_heap_templates_listing(self) -> None:
        messages = self._run_bridge([{"id": 1, "method": "heap_templates", "params": {}}])
        reply = self._rpc(messages, 1)
        self.assertTrue(reply["ok"])
        templates = reply["result"]["templates"]
        self.assertGreaterEqual(len(templates), 15)
        ids = {item["template_id"] for item in templates}
        self.assertIn("tcache_poison_safe_linking", ids)
        self.assertIn("house_of_botcake", ids)
        self.assertIn("basic_heap_layout", ids)

    def test_heap_replay_tcache_chain(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load",
             "params": {"template_id": "basic_tcache_chain"}},
        ])
        reply = self._rpc(messages, 1)
        self.assertTrue(reply["ok"], reply.get("error"))
        state = reply["result"]
        steps = state["steps"]
        self.assertEqual(len(steps), 7)
        final = steps[-1]
        self.assertEqual(final["bins"]["tcache"].get("0x70"), ["C", "B", "A"])
        chunk_ids = [chunk["chunk_id"] for chunk in final["chunks"]]
        self.assertIn("A", chunk_ids)
        first = steps[1]["chunks"][0]
        for key in ("chunk_id", "physical_id", "address", "chunk_size", "view_kind", "fields", "regions"):
            self.assertIn(key, first)
        self.assertTrue(final["bin_rows"])
        self.assertIn("groups", final)

    def test_heap_replay_from_source_analysis(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": TCACHE_CHAIN_SOURCE}},
        ])
        reply = self._rpc(messages, 1)
        self.assertTrue(reply["ok"], reply.get("error"))
        state = reply["result"]
        kinds = [op["kind"] for op in state["operations"]]
        self.assertEqual(kinds, ["alloc", "alloc", "free", "free"])
        analysis = state["analysis"]
        self.assertEqual(len(analysis["bindings"]), 4)
        self.assertTrue(analysis["valid"])

    def test_heap_template_steps_all_serialize(self) -> None:
        """Every bundled template must replay and serialize without error."""
        requests = [
            {"id": index + 1, "method": "heap_load",
             "params": {"template_id": template_id,
                        "allocator": {"version": "2.27", "arch": "amd64",
                                      "simulation_mode": "plan"}}}
            for index, template_id in enumerate((
                "basic_heap_layout", "house_of_force", "house_of_lore",
                "house_of_orange", "house_of_botcake", "stdout_environ_stack",
                "setcontext_orw",
            ))
        ]
        messages = self._run_bridge(requests)
        for request in requests:
            reply = self._rpc(messages, request["id"])
            self.assertTrue(reply["ok"], f"{request['params']['template_id']}: {reply.get('error')}")
            self.assertGreaterEqual(len(reply["result"]["steps"]), 2)

    # ------------------------------------------------------------------
    # correction + self-learning

    def test_canvas_correction_replays_and_infers_rule(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load",
             "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_correct", "params": {}},  # placeholder, replaced below
        ])
        # step-1 chunk size field address comes from the load result; run a
        # second bridge round-trip with the concrete address.
        load = self._rpc(messages, 1)
        self.assertTrue(load["ok"], load.get("error"))
        chunk = load["result"]["steps"][1]["chunks"][0]
        size_field = next(f for f in chunk["fields"] if f["name"] == "size")
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load",
             "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_correct", "params": {
                "step": 1,
                "patch": {
                    "address": size_field["address"],
                    "value_int": 0x71,
                    "length": 8,
                    "field": "size",
                    "object_id": chunk["physical_id"],
                    "note": "用户画布校正",
                },
                "context": {"helper": "add", "kind": "alloc", "corrected_kind": "alloc"},
            }},
        ])
        reply = self._rpc(messages, 2)
        self.assertTrue(reply["ok"], reply.get("error"))
        result = reply["result"]
        self.assertTrue(result["accepted"], result.get("issues"))
        self.assertEqual(result["status"].upper(), "VALID")
        self.assertGreaterEqual(len(result["steps"]), 1)
        self.assertTrue(result["corrections"])
        added = result["learned_rules_added"]
        self.assertTrue(added)
        self.assertEqual(added[0]["scope"], "scene")
        self.assertFalse(added[0]["requires_confirmation"])
        self.assertTrue(added[0]["reason"])

    def test_heap_overflow_paint_template(self) -> None:
        """basic_overflow_paint: each +8 edit paints one more fixed cell of B."""
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load",
             "params": {"template_id": "basic_overflow_paint"}},
        ])
        reply = self._rpc(messages, 1)
        self.assertTrue(reply["ok"], reply.get("error"))
        steps = reply["result"]["steps"]
        self.assertEqual(len(steps), 7)
        # 第一次 +8 → only B.prev_size covered; 第四次 → user rows covered too.
        first = steps[3]
        first_ranges = [span["physical_start"] for span in first["paint_spans"]
                        if span["visual_kind"] == "cross_write"]
        self.assertEqual(len(first_ranges), 1)
        last = steps[-1]
        cross = [span for span in last["paint_spans"]
                 if span["visual_kind"] == "cross_write"]
        covered = {(span["physical_start"], span["physical_end"]) for span in cross}
        self.assertGreaterEqual(len(covered), 3)
        b = next(chunk for chunk in last["chunks"] if chunk["chunk_id"] == "B")
        # prev_size + size + both user qwords of B are painted (16-byte user row
        # yields one merged span) — the row structure itself never changes.
        self.assertTrue(any(start.endswith("b0") for start, _ in covered))
        self.assertTrue(any(start.endswith("c0") for start, _ in covered))

    def test_learning_semantic_contract_via_r2s_match(self) -> None:
        """① 语义识别纠错：size 校正的 r2s 预像命中调用点实参 → 学 HelperContract 并整题重算。"""
        source = "def add(idx, size, content):\n    pass\nadd(0, 0x80, 0x100)\n"
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
            {"id": 2, "method": "heap_state", "params": {}},
        ])
        load = self._rpc(messages, 1)
        self.assertTrue(load["ok"], load.get("error"))
        state = self._rpc(messages, 2)["result"]
        chunk = state["steps"][1]["chunks"][0]
        size_field = next(f for f in chunk["fields"] if f["name"] == "size")
        # analyzer 误取 0x80（chunk 0x90）；真实语义 size=第三参 0x100（chunk 0x110）
        self.assertEqual(chunk["chunk_size"], "0x90")
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
            {"id": 2, "method": "heap_correct", "params": {
                "step": 1,
                "patch": {"address": size_field["address"], "value_int": 0x110,
                          "length": 8, "field": "size", "object_id": chunk["physical_id"]},
                "context": {"helper": "add"},
            }},
        ])
        reply = self._rpc(messages, 2)
        self.assertTrue(reply["ok"], reply.get("error"))
        learning = reply["result"]["learning"]
        self.assertEqual(learning["intent"], "semantic_contract")
        self.assertEqual(learning["confidence"], "USER_CONFIRMED")
        self.assertTrue(learning["reanalyzed"])
        learned = learning["learned"]
        self.assertEqual(learned["kind"], "helper_contract")
        self.assertEqual(learned["roles"]["size"]["position"], 2)
        self.assertEqual(learned["roles"]["size"]["parameter"], "content")
        # 重算后识别直接正确：chunk 0x110，观测补丁作为症状一并清空
        self.assertEqual(reply["result"]["steps"][1]["chunks"][0]["chunk_size"], "0x110")
        self.assertEqual(len(reply["result"]["corrections"]), 0)
        self.assertTrue(reply["result"]["episodes"])
        self.assertTrue(reply["result"]["helper_contracts"])

    def test_learning_observed_state_for_template(self) -> None:
        """② 物理状态纠错：模板场景无源码可追踪 → 仅 USER_OBSERVED 写入，不碰契约。"""
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load",
             "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_state", "params": {}},
        ])
        state = self._rpc(messages, 2)["result"]
        chunk = state["steps"][1]["chunks"][0]
        size_field = next(f for f in chunk["fields"] if f["name"] == "size")
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load",
             "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_correct", "params": {
                "step": 1,
                "patch": {"address": size_field["address"], "value_int": 0x421,
                          "length": 8, "field": "size", "object_id": chunk["physical_id"]},
                "context": {"helper": "add"},
            }},
        ])
        reply = self._rpc(messages, 2)
        self.assertTrue(reply["ok"])
        learning = reply["result"]["learning"]
        self.assertEqual(learning["intent"], "observed_state")
        self.assertFalse(learning["reanalyzed"])
        self.assertEqual(learning["learned"]["kind"], "observed_state")
        self.assertEqual(len(reply["result"]["helper_contracts"]), 0)
        # 观测补丁保留（本题状态推进）
        self.assertEqual(len(reply["result"]["corrections"]), 1)

    def test_learning_derivation_rule_edit_offset(self) -> None:
        """③ 推导规则纠错：edit user 区校正 + helper 体文本数据流 → EDIT.offset=0 规则。"""
        source = ("def add(idx, size, content):\n    pass\n"
                  "def edit(idx, data):\n    write(ptr[idx], data, len(data))\n"
                  "add(0, 0x80, b\"A\")\nedit(0, b\"B\")\n")
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
            {"id": 2, "method": "heap_state", "params": {}},
        ])
        state = self._rpc(messages, 2)["result"]
        chunk = next(c for c in state["steps"][2]["chunks"] if c["lifecycle"] == "allocated")
        user_field = next(f for f in chunk["fields"] if f["name"].startswith("user"))
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
            {"id": 2, "method": "heap_correct", "params": {
                "step": 2,
                "patch": {"address": user_field["address"], "data_hex": "4242",
                          "length": 2, "field": "user_area", "object_id": chunk["physical_id"]},
                "context": {"helper": "edit"},
            }},
        ])
        reply = self._rpc(messages, 2)
        self.assertTrue(reply["ok"], reply.get("error"))
        learning = reply["result"]["learning"]
        self.assertEqual(learning["intent"], "derivation_rule")
        learned = learning["learned"]
        self.assertEqual(learned["kind"], "learned_rule")
        self.assertEqual(learned["target"], "EDIT.offset")
        self.assertIn("STATIC_DATAFLOW_TEXT", learned["evidence"])
        # 规则已应用：edit 操作 meta.offset = 0
        edit_op = next(op for op in reply["result"]["operations"] if op["kind"] == "edit")
        self.assertEqual(edit_op["meta"].get("offset"), "0")

    def test_semantic_round_trip_reverse_solve_and_simulate(self) -> None:
        """Semantic Round Trip：画布物理写入 → 反向求解 → 推演 → 溯源/历史。"""
        source = ("def add(idx, size, content):\n    pass\n"
                  "add(0, 0x80, b\"A\")\nadd(1, 0x80, b\"B\")\n")
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
            {"id": 2, "method": "heap_state", "params": {}},
        ])
        state = self._rpc(messages, 2)["result"]
        chunks = sorted(state["steps"][2]["chunks"], key=lambda item: int(item["heap_offset"], 16))
        chunk_b = chunks[1]
        target = next(field["address"] for field in chunk_b["fields"] if field["name"] == "size")
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
            {"id": 2, "method": "heap_reverse_edit", "params": {
                "step": 2, "address": target,
                "data_hex": "2104000000000000", "length": 8,
            }},
        ])
        reply = self._rpc(messages, 2)
        self.assertTrue(reply["ok"], reply.get("error"))
        solved = reply["result"]
        self.assertEqual(solved["python"], "edit(0, 0x88, p64(0x421))")
        self.assertEqual(solved["effects"][0]["chunk"], "B")
        self.assertEqual(solved["effects"][0]["field"], "size")
        self.assertTrue(solved["source"]["overflow"])
        # 推演：Canonical Operation 进入操作模型并重放
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
            {"id": 2, "method": "heap_apply_pending", "params": {
                "step": 2, "canonical": solved["canonical"], "python": solved["python"],
            }},
            {"id": 3, "method": "heap_field_provenance",
             "params": {"step": 3, "address": target}},
            {"id": 4, "method": "heap_chunk_history", "params": {"chunk": "B"}},
        ])
        applied = self._rpc(messages, 2)
        self.assertTrue(applied["ok"], applied.get("error"))
        chunk_b = next(c for c in applied["result"]["steps"][-1]["chunks"] if c["chunk_id"] == "B")
        self.assertEqual(chunk_b["chunk_size"], "0x420")
        provenance = self._rpc(messages, 3)
        chain = provenance["result"]["chain"]
        self.assertEqual(chain[0]["kind"], "alloc")
        self.assertEqual(chain[-1]["kind"], "cross_chunk_overwrite")
        self.assertEqual(chain[-1]["value"], "0x421")
        history = self._rpc(messages, 4)
        kinds = [item["kind"] for item in history["result"]["history"]]
        self.assertEqual(kinds, ["alloc", "write"])

    def test_helper_mapping_custom_names(self) -> None:
        """用户词典：addchunk→add 映射后，自定义函数名按对应语义识别。"""
        source = ("def addchunk(i, s, c):\n    pass\n"
                  "def deletechunk(i):\n    pass\n"
                  "addchunk(0, 0x80, b\"A\")\naddchunk(1, 0x80, b\"B\")\ndeletechunk(0)\n")
        # 未映射：addchunk/deletechunk 已进默认词表 → 直接识别
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": source}},
        ])
        state = self._rpc(messages, 1)["result"]
        kinds = [op["kind"] for op in state["operations"]]
        self.assertEqual(kinds, ["alloc", "alloc", "free"])
        # 完全陌生的名字（zengjia）：映射后识别
        strange = ("def zengjia(i, s, c):\n    pass\n"
                   "def shanchu(i):\n    pass\n"
                   "zengjia(0, 0x80, b\"A\")\nshanchu(0)\n")
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": strange}},
            {"id": 2, "method": "heap_mapping",
             "params": {"action": "add", "alias": "zengjia", "target": "alloc"}},
            {"id": 3, "method": "heap_mapping",
             "params": {"action": "add", "alias": "shanchu", "target": "free"}},
            {"id": 4, "method": "heap_mapping", "params": {"action": "list"}},
        ])
        before = self._rpc(messages, 1)["result"]
        self.assertEqual([op["kind"] for op in before["operations"]], [])
        mapped = self._rpc(messages, 3)["result"]
        kinds = [op["kind"] for op in mapped["operations"]]
        self.assertEqual(kinds, ["alloc", "free"])
        self.assertIn({"alias": "zengjia", "target": "alloc"},
                      mapped["mappings"])
        listing = self._rpc(messages, 4)
        self.assertEqual(len(listing["result"]["mappings"]), 2)
        # 无效目标语义被拒绝
        messages = self._run_bridge([
            {"id": 1, "method": "heap_mapping",
             "params": {"action": "add", "alias": "x", "target": "nonsense"}},
        ])
        reply = self._rpc(messages, 1)
        self.assertFalse(reply["ok"])

    def test_rejected_correction_reports_issues_without_learning(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load",
             "params": {"template_id": "basic_heap_layout"}},
            {"id": 2, "method": "heap_correct", "params": {
                "step": 1,
                "patch": {"address": "0xdeadbeef", "value_int": 1, "length": 8, "field": "size"},
                "context": {},
            }},
        ])
        reply = self._rpc(messages, 2)
        self.assertTrue(reply["ok"])
        self.assertFalse(reply["result"]["accepted"])
        self.assertTrue(reply["result"]["issues"])

    def test_explicit_learn_updates_replay(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "heap_load", "params": {"source": TCACHE_CHAIN_SOURCE}},
            {"id": 2, "method": "heap_learn",
             "params": {"function": "add", "semantic": "free"}},
            {"id": 3, "method": "heap_state", "params": {}},
        ])
        learned = self._rpc(messages, 2)
        self.assertTrue(learned["ok"], learned.get("error"))
        self.assertTrue(learned["result"]["learned_rules"])
        state = self._rpc(messages, 3)
        kinds = [op["kind"] for op in state["result"]["operations"]]
        self.assertEqual(kinds, ["free", "free", "free", "free"])

    def test_heap_save_open_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "scene.json")
            messages = self._run_bridge([
                {"id": 1, "method": "heap_load", "params": {"source": TCACHE_CHAIN_SOURCE}},
                {"id": 2, "method": "heap_save", "params": {"path": path}},
                {"id": 3, "method": "heap_open", "params": {"path": path}},
            ])
            opened = self._rpc(messages, 3)
            self.assertTrue(opened["ok"], opened.get("error"))
            self.assertGreaterEqual(len(opened["result"]["steps"]), 5)

    # ------------------------------------------------------------------
    # IOFILE

    def test_iofile_layout_and_validation(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "iofile_layout", "params": {"version": "2.35"}},
            {"id": 2, "method": "iofile_validate", "params": {
                "version": "2.35", "name": "vtable", "value": "0x555555554010",
                "observed": False,
                "mapped_ranges": [["0x555555554000", "0x555555558000"]],
            }},
            {"id": 3, "method": "iofile_validate", "params": {
                "version": "2.35", "name": "vtable", "value": "0x2",
            }},
            {"id": 4, "method": "iofile_analyze",
             "params": {"source": "io.stdout = p64(0xfbad1800)\n"}},
        ])
        layout = self._rpc(messages, 1)
        self.assertTrue(layout["ok"])
        names = [field["name"] for field in layout["result"]["fields"]]
        self.assertIn("_flags", names)
        self.assertIn("vtable", names)
        valid = self._rpc(messages, 2)
        self.assertEqual(valid["result"]["status"], "VALID")
        invalid = self._rpc(messages, 3)
        self.assertEqual(invalid["result"]["status"], "INVALID")
        analyze = self._rpc(messages, 4)
        self.assertTrue(analyze["ok"])
        self.assertTrue(analyze["result"]["evidence"])

    # ------------------------------------------------------------------
    # fmt / cyclic / convert

    def test_fmt_offset_and_plan(self) -> None:
        # find_fmt_offset enumerates printed hex tokens positionally; the
        # 6th printed value must contain the 0x41414141 marker.
        tokens = ["0x1", "0x2", "0x3", "0x4", "0x5",
                  "0x4141414141414141", "0x7ffff7a52290"]
        messages = self._run_bridge([
            {"id": 1, "method": "fmt_offset",
             "params": {"probe_output": " ".join(tokens)}},
            {"id": 2, "method": "fmt_plan",
             "params": {"target": "0x601000", "value": "0x7ffff7a52290"}},
        ])
        offset = self._rpc(messages, 1)
        self.assertTrue(offset["ok"], offset.get("error"))
        self.assertEqual(offset["result"]["offset"], 6)
        plan = self._rpc(messages, 2)
        self.assertTrue(plan["ok"])
        self.assertEqual(len(plan["result"]["plan"]["parts"]), 4)

    def test_cyclic_and_convert(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "cyclic_pattern", "params": {"size": 64, "n": 4}},
            {"id": 2, "method": "cyclic_find", "params": {"value": "0x61616162"}},
            {"id": 3, "method": "convert",
             "params": {"mode": "int", "value": "0x7ffff7a52290", "bits": 64}},
        ])
        pattern = self._rpc(messages, 1)
        self.assertTrue(pattern["result"]["pattern"].startswith("aaaabaaacaaadaaaeaaafaaa"))
        find = self._rpc(messages, 2)
        self.assertEqual(find["result"]["offset"], 4)
        convert = self._rpc(messages, 3)
        self.assertTrue(convert["result"]["results"])

    def test_leak_derive(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "leak_derive",
             "params": {"address": "0x7ffff7a52290", "offset": "0x52290"}},
        ])
        reply = self._rpc(messages, 1)
        self.assertTrue(reply["ok"], reply.get("error"))
        self.assertEqual(reply["result"]["libc_base"], 0x7FFFF7A00000)
        self.assertIn("-", reply["result"]["formula"])

    # ------------------------------------------------------------------
    # syscall / srop plan offline halves

    def test_syscall_table(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "syscall_table", "params": {"arch": "amd64"}},
        ])
        reply = self._rpc(messages, 1)
        names = {item["name"] for item in reply["result"]["syscalls"]}
        self.assertIn("read", names)
        self.assertIn("execve", names)

    def test_srop_plan_rejected_without_gadgets_is_clean(self) -> None:
        messages = self._run_bridge([
            {"id": 1, "method": "srop_plan", "params": {}},
        ])
        reply = self._rpc(messages, 1)
        self.assertTrue(reply["ok"], "SROP 计划在无 gadget 时应返回不可执行计划而非崩溃")
        self.assertIn("plan", reply["result"])


if __name__ == "__main__":
    unittest.main()
