"""Training-data layer tests — Case Export / Review 层 / family 级 split。"""
from __future__ import annotations

import unittest

from pwncraft.features.heapviz.bridge_session import HeapSession
from pwncraft.features.heapviz.dataset import (
    assign_splits,
    build_case_export,
    family_key,
    helper_cfg_fingerprint,
    normalize_review,
    validate_case,
    validate_review_against_case,
)


_SOURCE = """
def add(idx, size, content):
    chunks[idx] = malloc(size)
def mystery(idx, blob):
    pass
add(0, 0x80, b"AAAA")
add(1, 0x80, b"BBBB")
mystery(1, b"CC")
"""


def _session() -> HeapSession:
    session = HeapSession()
    session.load(source=_SOURCE, allocator={"profile_id": "glibc-2.31-amd64"})
    return session


def _unbound_line(session: HeapSession, function: str) -> int:
    for entry in session.analysis.recognition_report["candidates"]:
        if entry["function"] == function and entry["verdict"] != "recognized":
            return int(entry["line"])
    raise AssertionError(f"{function} 没有未绑定语义的候选")


class CaseExportTests(unittest.TestCase):
    def test_export_schema_and_revisions(self) -> None:
        session = _session()
        case = session.export_case(
            target={"binary_sha256": "b" * 64, "libc_sha256": "c" * 64, "arch": "amd64"},
            challenge_family="demo",
        )
        # 用户固定的导出结构：顶层键一个不少。
        for key in ("schema_version", "case_id", "target", "engine", "input",
                    "recognition", "helper_contracts", "canonical_ops",
                    "snapshots", "corrections", "learning_episodes"):
            self.assertIn(key, case)
        self.assertEqual(case["schema_version"], "1.0")
        # engine/revision 必须随样本保存 —— 三个月后还能归因。
        for key in ("version", "recognizer_revision",
                    "allocator_profile_id", "allocator_profile_revision"):
            self.assertTrue(str(case["engine"][key] or ""), f"engine.{key} 不能为空")
        self.assertEqual(case["engine"]["allocator_profile_id"], "glibc-2.31-amd64")
        self.assertEqual(case["target"]["binary_sha256"], "b" * 64)
        self.assertEqual(case["input"]["exp_source"], _SOURCE)
        self.assertTrue(case["snapshots"])
        self.assertTrue(case["recognition"]["candidates"])
        self.assertEqual(case["dedup"]["challenge_family"], "demo")
        self.assertTrue(case["dedup"]["helper_cfg_fingerprint"])
        issues = validate_case(case)
        self.assertEqual(issues, [])

    def test_case_id_is_deterministic_per_source_and_binary(self) -> None:
        first = _session().export_case(target={"binary_sha256": "x"})
        second = _session().export_case(target={"binary_sha256": "x"})
        self.assertEqual(first["case_id"], second["case_id"])
        other = _session().export_case(target={"binary_sha256": "y"})
        self.assertNotEqual(first["case_id"], other["case_id"])

    def test_validate_case_rejects_missing_revisions(self) -> None:
        session = _session()
        case = session.export_case()
        case["engine"]["recognizer_revision"] = ""
        issues = validate_case(case)
        self.assertTrue(any("recognizer_revision" in issue for issue in issues))

    def test_validation_flags_out_of_range_checkpoint(self) -> None:
        session = _session()
        case = session.export_case()
        case["learning_episodes"] = [{"checkpoint": 999}]
        issues = validate_case(case)
        self.assertTrue(any("checkpoint" in issue for issue in issues))

    def test_helper_cfg_fingerprint_groups_menu_renames(self) -> None:
        original = "def add(a, b):\n    chunks[a] = malloc(b)\nadd(1, 0x20)\n"
        renamed = "def buy_goods(a, b):\n    chunks[a] = malloc(b)\nbuy_goods(1, 0x20)\n"
        mutated = "def add(a, b):\n    chunks[a] = free(b)\nadd(1, 0x20)\n"
        self.assertEqual(helper_cfg_fingerprint(original), helper_cfg_fingerprint(renamed))
        self.assertNotEqual(helper_cfg_fingerprint(original), helper_cfg_fingerprint(mutated))


class ReviewLayerTests(unittest.TestCase):
    def _review(self, session: HeapSession, **overrides):
        line = _unbound_line(session, "mystery")
        payload = {
            "review_id": "R17",
            "issue_type": "helper_semantic",
            "target": {"source_line": line, "function": "mystery"},
            "before": {"verdict": "unknown"},
            "proposed": {"semantic": "edit", "roles": ["index", "data"]},
            "confidence": 0.93,
            "evidence": ["runtime: menu trace 2=>edit"],
            "verdict": "proposed",
        }
        payload.update(overrides)
        return normalize_review(payload)

    def test_import_review_does_not_touch_snapshots(self) -> None:
        session = _session()
        before = [snapshot.step for snapshot in session.snapshots]
        session.import_review(self._review(session))
        self.assertEqual([snapshot.step for snapshot in session.snapshots], before)
        self.assertEqual(len(session.reviews), 1)
        self.assertEqual(session.reviews[0]["verdict"], "proposed")
        self.assertEqual(session.reviews[0]["review_id"], "R17")

    def test_review_pipeline_accepts_validated_proposal(self) -> None:
        session = _session()
        session.import_review(self._review(session))
        result = session.apply_review("R17")
        review = result["review"]
        self.assertEqual(review["verdict"], "accepted")
        self.assertTrue(review["validation"]["target_hit"])
        self.assertEqual(review["validation"]["issues"], [])

    def test_review_without_evidence_stops_at_validated(self) -> None:
        session = _session()
        session.import_review(self._review(session, evidence=[]))
        review = session.apply_review("R17")["review"]
        self.assertEqual(review["verdict"], "validated")
        # 人工确认补足证据门 → accepted
        review = session.apply_review("R17", human_confirmed=True)["review"]
        self.assertEqual(review["verdict"], "accepted")

    def test_review_breaking_recognition_is_rejected(self) -> None:
        session = _session()
        # mystery 已经通过标注绑定为 edit；提议 ignore 会让已识别回退。
        line = _unbound_line(session, "mystery")
        session.label_recognition(line, "mystery", "edit", ["index", "data"])
        line = next(entry["line"] for entry in session.analysis.recognition_report["candidates"]
                    if entry["function"] == "mystery")
        session.import_review({
            "review_id": "R20",
            "issue_type": "miscalled_candidate",
            "target": {"source_line": int(line), "function": "mystery"},
            "proposed": {"semantic": "ignore"},
            "evidence": ["guess"],
        })
        review = session.apply_review("R20")["review"]
        self.assertEqual(review["verdict"], "rejected")
        self.assertTrue(any("回退" in issue or "目标未命中" in issue
                            for issue in review["validation"]["issues"]))
        # 快照层依旧未被 review 污染
        self.assertFalse(session.snapshots[-1].aborted)

    def test_static_gate_rejects_unknown_reference(self) -> None:
        session = _session()
        case = session.export_case(include_snapshots=False)
        review = normalize_review({
            "issue_type": "helper_semantic",
            "target": {"source_line": 9999, "function": "mystery"},
            "proposed": {"semantic": "alloc"},
        })
        issues = validate_review_against_case(review, case)
        self.assertTrue(any("source_line" in issue for issue in issues))


class RecognitionLabelTests(unittest.TestCase):
    _SHIFT_SOURCE = """
def rewrap(a, b, c):
    pass
rewrap(0, 0x80, b"AA")
rewrap(1, 0x80, b"BB")
"""

    def _shift_session(self) -> HeapSession:
        session = HeapSession()
        session.load(source=self._SHIFT_SOURCE, allocator={"version": "2.31"})
        return session

    def _rewrap_line(self, session: HeapSession) -> int:
        for entry in session.analysis.recognition_report["candidates"]:
            if entry["function"] == "rewrap" and entry["verdict"] != "recognized":
                return int(entry["line"])
        raise AssertionError("rewrap 没有未绑定语义的候选")

    def test_label_binds_semantic_and_roles(self) -> None:
        session = _session()
        line = _unbound_line(session, "mystery")
        state = session.label_recognition(line, "mystery", "edit", ["index", "data"],
                                          source_text="mystery(1, b'CC')")
        correction = state["recognition_correction"]
        self.assertEqual(correction["before"]["verdict"], "unknown")
        self.assertEqual(correction["after"]["verdict"], "recognized")
        self.assertEqual(correction["after"]["kind"], "edit")
        self.assertEqual(correction["allocator_profile"], "glibc-2.31-amd64")
        self.assertTrue(correction["recognizer_revision"])
        self.assertEqual(len(session.recognition_corrections), 1)

    def test_roles_keep_position_when_arg0_is_unknown(self) -> None:
        """arg0 未标注时必须以 null 占位，绝不能压缩成 ['size','data']。

        rewrap(0, 0x80, b"AA") 标成 {arg0:null, arg1:size, arg2:data} 后，
        回放出的 alloc 必须 index="0"（arg0）、size=0x80（arg1）—— 若角色
        错位成 arg0=size，index/size 会整体左移一格，这是训练集致命错标。
        """
        session = self._shift_session()
        line = self._rewrap_line(session)
        state = session.label_recognition(
            line, "rewrap", "alloc", {"arg0": None, "arg1": "size", "arg2": "data"},
        )
        correction = state["recognition_correction"]
        self.assertEqual(
            correction["roles"], {"arg0": None, "arg1": "size", "arg2": "data"},
        )
        self.assertEqual(correction["after"]["verdict"], "recognized")
        first_alloc = next(op for op in state["operations"] if op["kind"] == "alloc")
        self.assertEqual(str(first_alloc["index"]), "0")
        self.assertEqual(first_alloc["request_size"], "0x80")

    def test_roles_accept_list_and_dict_forms(self) -> None:
        session = self._shift_session()
        line = self._rewrap_line(session)
        state = session.label_recognition(line, "rewrap", "edit", ["index", None, "data"])
        self.assertEqual(
            state["recognition_correction"]["roles"],
            {"arg0": "index", "arg1": None, "arg2": "data"},
        )

    def test_mapping_rules_keep_none_slots(self) -> None:
        session = self._shift_session()
        session.set_helper_mapping("rewrap", "free", "index,,")
        rule = next(item for item in session._mapping_rules()
                    if item["matcher"]["function"] == "rewrap")
        self.assertEqual(rule["output"]["roles"], ["index", None, None])

    def test_ignore_label_persists_across_reanalysis(self) -> None:
        session = _session()
        line = _unbound_line(session, "mystery")
        session.label_recognition(line, "mystery", "ignore")
        session.load(source=session.source)   # 重新识别，ignore 规则必须仍然生效
        entry = next(item for item in session.analysis.recognition_report["candidates"]
                     if item["function"] == "mystery")
        self.assertEqual(entry["verdict"], "ignored")

    def test_labeled_correction_lands_in_case_export(self) -> None:
        session = _session()
        line = _unbound_line(session, "mystery")
        session.label_recognition(line, "mystery", "edit", ["index", "data"])
        case = session.export_case()
        self.assertEqual(len(case["recognition_corrections"]), 1)
        self.assertEqual(case["recognition_corrections"][0]["semantic"], "edit")


class CorrectionEpisodeFieldsTests(unittest.TestCase):
    def test_episode_carries_trainable_context(self) -> None:
        session = _session()
        session.label_recognition(_unbound_line(session, "mystery"), "mystery", "edit")
        # 校正第二步的 add：该调用点的识别报告有语义评分，前后调用点都在。
        checkpoint = 2
        snapshot = session.snapshots[checkpoint]
        allocated = [chunk for chunk in snapshot.chunks.values() if chunk.lifecycle == "allocated"]
        target = allocated[-1]   # 最近一次分配的 chunk
        size_field = next(field for field in target.fields if field.name.startswith("size"))
        result = session.correct(checkpoint, {
            "address": size_field.address,
            "field": "size",
            "object_id": target.physical_id,
            "value_int": 0x91,
            "length": 8,
            "note": "overflow 覆盖",
        }, context={"helper": "add", "kind": "alloc", "corrected_kind": "alloc"})
        self.assertTrue(result["accepted"])
        episode = session.episodes[-1]
        # 「可训练」字段：上下文 + 系统为什么得到 A + 角色绑定，全部在场。
        for field_name in ("function_fingerprint", "callsite_fingerprint",
                           "parameter_names", "argument_expressions",
                           "role_candidates_before", "role_binding_before",
                           "role_binding_after", "previous_op", "next_op",
                           "target_fingerprint", "allocator_profile"):
            self.assertTrue(episode.get(field_name) not in (None, "", [], {}),
                            f"episode.{field_name} 不应为空")
        self.assertEqual(episode["parameter_names"], ["idx", "size", "content"])
        self.assertEqual(episode["role_binding_before"], {"index": 0, "size": 1, "data": 2})
        self.assertEqual(
            [(item["kind"], item["score"]) for item in episode["role_candidates_before"]],
            [("alloc", 1.0)],
        )
        self.assertEqual(episode["before_value"], size_field.value)
        self.assertTrue(episode["after_value"])


class SplitAssignmentTests(unittest.TestCase):
    def test_family_stays_whole_across_variants(self) -> None:
        # babyheap 2018 / 2019 / 博客复制版 / 改菜单版 —— 同族必须同 split。
        variants = ["babyheap-2018", "babyheap-2019", "babyheap-blog-copy", "babyheap-renamed"]
        # Variants need the same explicit family key. Distinct family keys may
        # legitimately land in different splits when the seed changes.
        cases = [{"case_id": variant, "dedup": {"challenge_family": "babyheap"}}
                 for variant in variants]
        cases += [{"dedup": {"challenge_family": f"fam{index}"}} for index in range(16)]
        for seed in ("pwncraft-v1", "dataset-regression-2", "dataset-regression-3"):
            with self.subTest(seed=seed):
                assignment = assign_splits(cases, seed=seed)
                splits = {assignment[family_key(case)] for case in cases[:len(variants)]}
                self.assertEqual(len(splits), 1, "同一 challenge family 被拆进了不同 split")
                self.assertEqual(len(assignment), 17)

    def test_split_is_deterministic_and_covers_all_splits(self) -> None:
        cases = [{"dedup": {"challenge_family": f"family-{index}"}} for index in range(40)]
        first = assign_splits(cases)
        second = assign_splits(cases)
        self.assertEqual(first, second)
        from collections import Counter
        counts = Counter(first.values())
        self.assertTrue(all(counts[kind] > 0 for kind in ("train", "validation", "test")))
        self.assertGreater(counts["train"], counts["validation"])
        self.assertGreater(counts["validation"], 0)

    def test_split_falls_back_to_cfg_fingerprint(self) -> None:
        source = "def add(a, b):\n    chunks[a] = malloc(b)\nadd(1, 0x20)\n"
        key = helper_cfg_fingerprint(source)
        cases = [{"dedup": {"helper_cfg_fingerprint": key}},
                 {"dedup": {"helper_cfg_fingerprint": key}}]
        assignment = assign_splits(cases)
        self.assertEqual(len(assignment), 1)


if __name__ == "__main__":
    unittest.main()
