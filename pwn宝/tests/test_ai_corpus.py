from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pwnbao.features.ai import (
    AIAnalysisRequest,
    AIKnowledgeStore,
    AIProposal,
    CorpusEvaluator,
    CorpusManifest,
    LocalSourceCorpusScanner,
    LearnedRule,
    PdfWriteupCorpusScanner,
    ProvenFeedbackCompiler,
    StrictProposalReplayer,
    validate_ai_response,
)
from pwnbao.features.heapviz import GlibcHeapEngine, HeapOperationKind, analyze_heap_source, build_allocator_config
from pwnbao.tools.heap_ai_corpus import main as corpus_main

class HeapAICorpusTests(unittest.TestCase):
    def test_pdf_writeup_scanner_recovers_indented_heap_exp_without_copying_pdf(self) -> None:
        pages = ["""pwn 159
tcache chunk heap
from pwn import *
def Add(size, content):
         io.sendline(str(size))
        io.send(content)
def Delete(idx):
        io.sendline(str(idx))
Add(0x20, b'A')
Delete(0)
讲解结束
"""]
        cases = PdfWriteupCorpusScanner.extract_cases("local.pdf", pages)
        self.assertEqual(cases[0].challenge_id, "159")
        source = PdfWriteupCorpusScanner.extract_python(cases[0].text)
        self.assertIn("Add(0x20, b'A')", source)
        self.assertIn("Delete(0)", source)
        self.assertTrue(PdfWriteupCorpusScanner.is_heap_source(source, cases[0].text, "159"))

    def test_local_source_scanner_builds_manifest_and_prompt_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            solve_dir = root / "traditional"
            solve_dir.mkdir()
            source = solve_dir / "solve.py"
            source.write_text(
                "from pwn import *\n"
                "# heap tcache copy primitive\n"
                "def create(size, idx):\n"
                "    io.sendlineafter(b'choice: ', b'1')\n"
                "    io.sendline(str(size).encode())\n"
                "    io.sendline(str(idx).encode())\n\n"
                "def destroy(idx):\n"
                "    io.sendlineafter(b'choice: ', b'4')\n"
                "    io.sendline(str(idx).encode())\n\n"
                "def copy_chunk(src, dst, length):\n"
                "    io.sendlineafter(b'choice: ', b'7')\n"
                "    io.sendline(str(src).encode())\n"
                "    io.sendline(str(dst).encode())\n"
                "    io.sendline(str(length).encode())\n\n"
                "class StudentClient:\n"
                "    def edit_bio(self, size, payload):\n"
                "        io.sendline(str(size).encode())\n"
                "        io.send(payload)\n\n"
                "create(0x100, 0)\n"
                "destroy(0)\n"
                "copy_chunk(0, 1, 0x20)\n",
                encoding="utf-8",
            )
            markdown = root / "WRITEUP.md"
            markdown.write_text(
                "heap overlap\n\n"
                "```python\n"
                "from pwn import *\n"
                "add(0x68, b'A')\n"
                "delete(0)\n"
                "```\n",
                encoding="utf-8",
            )

            output = root / "out"
            result = LocalSourceCorpusScanner().scan(root, output)

            self.assertGreaterEqual(result["summary"]["heap_cases"], 2)
            manifest = CorpusManifest.load(Path(result["manifest"]))
            self.assertTrue(all(case.license == "local-user-provided" for case in manifest.cases))
            self.assertTrue(all(Path(case.source_uri).is_file() for case in manifest.cases))
            guidance = json.loads(Path(result["prompt_guidance"]).read_text(encoding="utf-8"))
            self.assertEqual(guidance["model"], "qwen3-coder-30b-a3b-instruct")
            self.assertIn("copy", guidance["discovered_helper_summary"]["by_semantic"])
            payloads = [
                json.loads(item["proposal"]["payload_json"])
                for item in guidance["rule_output_examples"]
                if item["proposal"]["action"] == "helper_mapping"
            ]
            self.assertTrue(any(item.get("semantic") == "copy" for item in payloads))
            self.assertTrue(any(item.get("function") == "edit_bio" and item.get("roles") == ["size", "data"] for item in payloads))
            self.assertTrue(any(item.get("function") == "edit_bio" for item in guidance["review_candidates"]))
            source_index = json.loads((output / "source_index.json").read_text(encoding="utf-8"))
            self.assertEqual(source_index["manifest"], str(output / "manifest.json"))

    def test_proven_feedback_compiler_promotes_only_after_independent_holdout(self) -> None:
        source = "def mystery(slot):\n    io.sendline(str(slot))\nadd(0x20, b'A')\nmystery(0)\n"
        config = build_allocator_config("amd64", "glibc 2.35")
        proposal = AIProposal(
            "map-mystery",
            "helper_mapping",
            0,
            0,
            "",
            confidence=0.95,
            helper_mapping={
                "semantic": "free",
                "function": "mystery",
                "roles": ["index"],
                "arity": 1,
                "keywords": [],
                "parameter_names": ["slot"],
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            compiler = ProvenFeedbackCompiler(store)
            analysis = analyze_heap_source(source)
            replay = StrictProposalReplayer(source, analysis, config).preview(proposal)
            self.assertTrue(replay.accepted, replay.message)
            first = compiler.compile(
                case_id="case-one",
                run_id="run-one",
                source=source,
                source_hash=hashlib.sha256(source.encode()).hexdigest(),
                proposal=proposal,
                replay=replay,
                model="qwen-test",
                prompt_version="test",
            )
            self.assertTrue(first.accepted)
            self.assertFalse(first.rule_enabled)
            second_source = "# independent holdout\n" + source
            second_analysis = analyze_heap_source(second_source)
            second_replay = StrictProposalReplayer(second_source, second_analysis, config).preview(proposal)
            second = compiler.compile(
                case_id="case-two",
                run_id="run-two",
                source=second_source,
                source_hash=hashlib.sha256(second_source.encode()).hexdigest(),
                proposal=proposal,
                replay=second_replay,
                model="qwen-test",
                prompt_version="test",
                holdout_passed=True,
            )
            self.assertTrue(second.rule_enabled)
            self.assertEqual(len(store.list_regression_fixtures()), 2)
            learned = analyze_heap_source(source, learned_rules=[store.list_rules()[0].to_dict()])
            self.assertEqual(learned.operations[1].kind.value, "free")

    def test_proven_feedback_compiler_aggressive_promotes_single_proven_case(self) -> None:
        source = "def mystery(slot):\n    io.sendline(str(slot))\nadd(0x20, b'A')\nmystery(0)\n"
        config = build_allocator_config("amd64", "glibc 2.35")
        proposal = AIProposal(
            "map-mystery",
            "helper_mapping",
            0,
            0,
            "",
            confidence=0.85,
            helper_mapping={
                "semantic": "free",
                "function": "mystery",
                "roles": ["index"],
                "arity": 1,
                "keywords": [],
                "parameter_names": ["slot"],
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            compiler = ProvenFeedbackCompiler(store)
            analysis = analyze_heap_source(source)
            replay = StrictProposalReplayer(source, analysis, config).preview(proposal)
            self.assertTrue(replay.accepted, replay.message)
            result = compiler.compile(
                case_id="case-one",
                run_id="run-one",
                source=source,
                source_hash=hashlib.sha256(source.encode()).hexdigest(),
                proposal=proposal,
                replay=replay,
                model="qwen-test",
                prompt_version="test",
                promotion_mode="aggressive",
            )
            self.assertTrue(result.accepted)
            self.assertTrue(result.rule_enabled)
            self.assertEqual(result.promotion["required_positive_cases"], 1)
            self.assertFalse(result.promotion["require_holdout"])
            rules = store.list_rules()
            self.assertEqual(rules[0].source, "qwen-strict-auto:aggressive")
            learned = analyze_heap_source(source, learned_rules=[rules[0].to_dict()])
            self.assertEqual(learned.operations[1].kind.value, "free")

    def test_strict_replayer_proves_snapshot_effect_and_rejects_noop(self) -> None:
        source = "add(0x20, b'A')\n"
        analysis = analyze_heap_source(source)
        config = build_allocator_config("amd64", "glibc 2.35")
        snapshots = GlibcHeapEngine(config).replay(analysis.operations)
        chunk_id = next(iter(snapshots[1].chunks))
        binding = analysis.bindings[0]
        replacement = analysis.operations[0].to_dict()
        replacement["request_size"] = "0x30"
        proposal = AIProposal(
            "resize",
            "replace_operation",
            binding.start,
            binding.end,
            binding.source_text,
            operation=replacement,
            snapshot_effect={
                "step": 1,
                "chunk": chunk_id,
                "field": "chunk_size",
                "current": "0x30",
                "expected": "0x40",
                "evidence": ["line 1"],
                "evidence_kind": "source",
                "provenance": "inferred",
            },
        )
        replayed = StrictProposalReplayer(source, analysis, config).preview(proposal)
        self.assertTrue(replayed.accepted, replayed.message)
        self.assertEqual(replayed.replayed_effect, "0x40")
        self.assertTrue(replayed.semantic_changed)

        no_op = StrictProposalReplayer(source, analysis, config).preview(
            AIProposal(
                "noop",
                "replace_operation",
                binding.start,
                binding.end,
                binding.source_text,
                operation=analysis.operations[0].to_dict(),
            )
        )
        self.assertFalse(no_op.accepted)
        self.assertIn("未改变 Heap IR", no_op.message)

        equivalent = analysis.operations[0].to_dict()
        equivalent["request_size"] = "32"
        equivalent["data"] = 'b"A"'
        numeric_no_op = StrictProposalReplayer(source, analysis, config).preview(
            AIProposal(
                "numeric-noop",
                "replace_operation",
                binding.start,
                binding.end,
                binding.source_text,
                operation=equivalent,
            )
        )
        self.assertFalse(numeric_no_op.accepted)
        self.assertIn("未改变 Heap IR", numeric_no_op.message)

    def test_strict_replayer_accepts_only_helper_rule_that_changes_ir(self) -> None:
        source = "add(0x20, b'A')\ntake(0)\n"
        analysis = analyze_heap_source(source)
        self.assertEqual(len(analysis.operations), 1)
        start = source.index("take(0)")
        proposal = AIProposal(
            "take-free",
            "helper_mapping",
            start,
            start + len("take(0)"),
            "take(0)",
            helper_mapping={
                "semantic": "free",
                "function": "take",
                "roles": ["index"],
                "arity": 1,
            },
        )
        result = StrictProposalReplayer(
            source,
            analysis,
            build_allocator_config("amd64", "glibc 2.35"),
        ).preview(proposal)
        self.assertTrue(result.accepted, result.message)
        self.assertEqual(result.operation_count, 2)
        self.assertTrue(result.learned_rule)

    def test_strict_replayer_rejects_candidate_that_targets_missing_chunk(self) -> None:
        source = "delete(0)\nadd(0x20, b'A')\n"
        analysis = analyze_heap_source(source)
        binding = analysis.bindings[0]
        replacement = analysis.operations[0].to_dict()
        replacement["chunk"] = "A"
        proposal = AIProposal(
            "premature-free",
            "replace_operation",
            binding.start,
            binding.end,
            binding.source_text,
            confidence=0.95,
            operation=replacement,
        )

        replay = StrictProposalReplayer(
            source,
            analysis,
            build_allocator_config("amd64", "glibc 2.35"),
        ).preview(proposal)

        self.assertFalse(replay.accepted)
        self.assertIn("free_unknown", replay.message)

    def test_strict_replayer_rejects_unproven_consolidate_context(self) -> None:
        source = "add(0x20, b'A')\n"
        analysis = analyze_heap_source(source)
        binding = analysis.bindings[0]
        proposal = AIProposal(
            "bad-consolidate",
            "insert_after",
            binding.start,
            binding.end,
            binding.source_text,
            confidence=0.95,
            operation={
                "kind": "consolidate",
                "meta": {"source": "heap_rule:allocator.consolidate"},
            },
        )

        replay = StrictProposalReplayer(
            source,
            analysis,
            build_allocator_config("amd64", "glibc 2.27"),
        ).preview(proposal)

        self.assertFalse(replay.accepted)
        self.assertIn("缺少可证明触发点", replay.message)

    def test_strict_replayer_rejects_lossy_replace_operation(self) -> None:
        source = "add(0x68, payload)\n"
        analysis = analyze_heap_source(source)
        binding = analysis.bindings[0]
        replacement = analysis.operations[0].to_dict()
        replacement["data"] = ""
        proposal = AIProposal(
            "lossy-alloc",
            "replace_operation",
            binding.start,
            binding.end,
            binding.source_text,
            confidence=0.95,
            operation=replacement,
        )

        replay = StrictProposalReplayer(
            source,
            analysis,
            build_allocator_config("amd64", "glibc 2.35"),
        ).preview(proposal)

        self.assertFalse(replay.accepted)
        self.assertIn("丢失已有静态事实", replay.message)

    def test_strict_replayer_rejects_duplicate_inserted_operation(self) -> None:
        source = "add(0x20, b'A')\ndelete(0)\n"
        analysis = analyze_heap_source(source)
        binding = analysis.bindings[1]
        duplicate = analysis.operations[1].to_dict()
        duplicate["op_id"] = ""
        duplicate["index"] = ""
        proposal = AIProposal(
            "duplicate-free",
            "insert_after",
            binding.start,
            binding.end,
            binding.source_text,
            confidence=0.95,
            operation=duplicate,
        )

        replay = StrictProposalReplayer(
            source,
            analysis,
            build_allocator_config("amd64", "glibc 2.35"),
        ).preview(proposal)

        self.assertFalse(replay.accepted)
        self.assertIn("重复了源码范围内已有 Heap IR", replay.message)

    def test_strict_replayer_rejects_op_rule_insert_on_mismatched_source_kind(self) -> None:
        source = "add(0x20, b'A')\n"
        analysis = analyze_heap_source(source)
        binding = analysis.bindings[0]
        proposal = AIProposal(
            "bad-show-anchor",
            "insert_after",
            binding.start,
            binding.end,
            binding.source_text,
            confidence=0.95,
            operation={
                "kind": "show",
                "chunk": "A",
                "index": "0",
                "meta": {"source": "heap_rule:op.show"},
            },
            heap_rule_call={
                "rule_id": "op.show",
                "arguments": {"chunk": "A", "index": 0},
                "placement": "insert_after",
            },
        )

        replay = StrictProposalReplayer(
            source,
            analysis,
            build_allocator_config("amd64", "glibc 2.35"),
        ).preview(proposal)

        self.assertFalse(replay.accepted)
        self.assertIn("源码锚点语义不匹配", replay.message)

    def test_strict_replayer_allows_consolidate_after_fastbin_free(self) -> None:
        source = "add(0x20, b'A')\ndelete(0)\n"
        analysis = analyze_heap_source(source)
        self.assertEqual(analysis.operations[1].kind, HeapOperationKind.FREE)
        binding = analysis.bindings[1]
        proposal = AIProposal(
            "fastbin-consolidate",
            "insert_after",
            binding.start,
            binding.end,
            binding.source_text,
            confidence=0.95,
            operation={
                "kind": "consolidate",
                "meta": {"source": "heap_rule:allocator.consolidate"},
            },
        )

        replay = StrictProposalReplayer(
            source,
            analysis,
            build_allocator_config("amd64", "glibc 2.23"),
        ).preview(proposal)

        self.assertTrue(replay.accepted, replay.message)
        self.assertTrue(replay.semantic_changed)
        self.assertIn("malloc_consolidate", replay.warnings)

    def test_repository_manifest_is_hash_locked_and_split_by_technique(self) -> None:
        manifest = CorpusManifest.load(Path("datasets/heap_ai/manifest.json"))
        self.assertEqual(len(manifest.cases), 23)
        self.assertEqual(sum(item.source_language == "python" for item in manifest.cases), 5)
        self.assertEqual(sum(item.source_language == "c" for item in manifest.cases), 18)
        technique_splits: dict[str, str] = {}
        for case in manifest.cases:
            self.assertEqual(len(case.source_hash), 64)
            self.assertEqual(technique_splits.setdefault(case.technique, case.split), case.split)

    def test_manifest_rejects_cross_split_technique_leakage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "exp.py"
            source.write_text("add(0x20, b'A')\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            payload = {
                "schema_version": 1,
                "cases": [
                    {
                        "case_id": "one",
                        "split": "train",
                        "technique": "same-technique",
                        "source_uri": str(source),
                        "source_hash": digest,
                    },
                    {
                        "case_id": "two",
                        "split": "holdout",
                        "technique": "same-technique",
                        "source_uri": str(source),
                        "source_hash": digest,
                    },
                ],
            }
            path = root / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "prevent leakage"):
                CorpusManifest.load(path)

    def test_snapshot_effect_schema_requires_evidence_and_forbids_observed_claim(self) -> None:
        source = "add(0x20, b'A')\n"
        base = {
            "proposal_id": "snapshot-size",
            "action": "replace_operation",
            "source_start": 0,
            "source_end": len(source.strip()),
            "source_text": source.strip(),
            "confidence": 0.9,
            "rationale": "source anchored",
            "operation": {"kind": "alloc", "chunk": "chunk_0", "request_size": "0x30", "data": "b'A'"},
            "snapshot_effect": {
                "step": 1,
                "chunk": "chunk_0",
                "field": "chunk_size",
                "current": "0x30",
                "expected": "0x40",
                "evidence": ["EXP add request at line 1"],
                "evidence_kind": "source",
                "provenance": "inferred",
            },
        }
        accepted, diagnostics = validate_ai_response(
            {"source_hash": "same", "proposals": [base]}, source, "same"
        )
        self.assertFalse(diagnostics)
        self.assertEqual(accepted[0].snapshot_effect["field"], "chunk_size")

        invalid = json.loads(json.dumps(base))
        invalid["snapshot_effect"]["evidence"] = []
        invalid["snapshot_effect"]["provenance"] = "observed"
        rejected, diagnostics = validate_ai_response(
            {"source_hash": "same", "proposals": [invalid]}, source, "same"
        )
        self.assertEqual(rejected, ())
        self.assertTrue(any("evidence" in item or "observed" in item for item in diagnostics))

    def test_request_carries_snapshot_and_pwndbg_evidence_and_changes_cache_identity(self) -> None:
        source = "add(0x20, b'A')\n"
        request = AIAnalysisRequest.build(
            1,
            source,
            {"version": "2.35"},
            {"valid": True},
            current_snapshot={"step": 1, "chunks": {"A": {"chunk_size": "0x30"}}},
            observed_heap={"chunks": [{"address": "0x55555000", "size": "0x30"}]},
            observed_diff={"mismatched": 0},
        )
        payload = request.prompt_payload()
        self.assertIn("current_snapshot", payload)
        self.assertIn("chunk_rows", payload["current_snapshot"])
        self.assertNotIn("chunks", payload["current_snapshot"])
        self.assertIn("pwndbg_observed", payload)
        self.assertIn("simulation_diff", payload)

    def test_knowledge_records_cases_runs_fixtures_and_promotes_after_holdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            case = {
                "case_id": "case-one",
                "source_uri": "local.py",
                "source_hash": "a" * 64,
                "split": "train",
                "technique": "custom-helper",
                "allocator": {"version": "2.35"},
            }
            store.upsert_corpus_case(case)
            self.assertEqual(store.list_corpus_cases()[0]["case_id"], "case-one")
            store.save_evaluation_run({"run_id": "run-one", "case_id": "case-one", "status": "completed"})
            store.add_snapshot_review({
                "case_id": "case-one",
                "run_id": "run-one",
                "proposal_signature": "sig",
                "decision": "accepted",
                "effect": {"field": "chunk_size"},
                "evidence": ["source"],
            })
            fixture = store.add_regression_fixture(
                feedback_id="fb-one",
                source_hash="a" * 64,
                category="helper_mapping",
                source_fragment="mystery(1)",
                expected={"semantic": "free"},
            )
            self.assertTrue(fixture["fixture_id"].startswith("fx_"))
            self.assertEqual(len(store.list_regression_fixtures()), 1)

            rule = LearnedRule("rule-promote", "free", {"function": "mystery", "arity": 1}, {"roles": ["index"]})
            first, status = store.review_rule_candidate(rule, case_id="case-one", feedback_id="fb-one")
            self.assertFalse(first.enabled)
            self.assertEqual(status["positive_cases"], 1)
            second, status = store.review_rule_candidate(
                rule,
                case_id="case-two",
                feedback_id="fb-two",
                holdout_passed=True,
            )
            self.assertTrue(second.enabled)
            self.assertTrue(status["eligible"])

    def test_static_corpus_run_is_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "exp.py"
            source.write_text("add(0x20, b'A')\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({
                "schema_version": 1,
                "cases": [{
                    "case_id": "basic-alloc",
                    "split": "train",
                    "technique": "basic-alloc",
                    "source_uri": str(source),
                    "source_hash": digest,
                    "expected_ir": [{"kind": "alloc"}],
                    "assertions": [{"step": 1, "field": "aborted", "expected": False}],
                }],
            }), encoding="utf-8")
            manifest = CorpusManifest.load(manifest_path)
            store = AIKnowledgeStore(root / "knowledge.sqlite3")
            evaluator = CorpusEvaluator(store)
            output = root / "out"
            first = evaluator.run(manifest, output)
            second = evaluator.run(manifest, output)
            self.assertEqual(first["failed"], 0)
            self.assertEqual(second["cases"][0]["status"], "cached")
            result = json.loads((output / "basic-alloc.json").read_text(encoding="utf-8"))
            self.assertEqual(result["metrics"]["assertions_passed"], 1)
            self.assertEqual(result["metrics"]["semantic_exact"], 1)

    def test_cli_rejects_wrong_loaded_model_before_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "exp.py"
            source.write_text("add(0x20, b'A')\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "cases": [{
                    "case_id": "model-check",
                    "split": "train",
                    "technique": "model-check",
                    "source_uri": str(source),
                    "source_hash": digest,
                }],
            }), encoding="utf-8")
            with patch(
                "pwnbao.tools.heap_ai_corpus.OpenAICompatibleProvider.list_models",
                return_value=("wrong-model",),
            ):
                result = corpus_main([
                    str(manifest),
                    "--output", str(root / "out"),
                    "--knowledge", str(root / "knowledge.sqlite3"),
                    "--with-ai",
                ])
            self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
