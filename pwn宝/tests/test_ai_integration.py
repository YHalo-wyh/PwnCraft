from __future__ import annotations

import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pwnbao.features.ai import (
    AIAnalysisCoordinator,
    AIAnalysisRequest,
    AIAnalysisResult,
    AIKnowledgeStore,
    AIProposal,
    AIProviderConfig,
    FeedbackRecord,
    LearnedRule,
    LocalAIProvider,
    OpenAICompatibleProvider,
    PromptBudget,
    ProviderError,
    validate_ai_response,
)
from pwnbao.features.ai.models import _compact_static_result
from pwnbao.features.heapviz import HeapOperationKind, analyze_heap_source


class _LMStudioStub(BaseHTTPRequestHandler):
    reject_structured_once = False
    post_count = 0
    last_authorization = ""

    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        type(self).last_authorization = self.headers.get("Authorization") or ""
        if self.path == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": "qwen-test"}]})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        type(self).post_count += 1
        type(self).last_authorization = self.headers.get("Authorization") or ""
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path != "/v1/chat/completions":
            self._json(404, {"error": "not found"})
            return
        if type(self).reject_structured_once and "response_format" in payload:
            type(self).reject_structured_once = False
            self._json(400, {"error": "structured output unavailable"})
            return
        user_message = next(item for item in reversed(payload["messages"]) if item.get("role") == "user")
        user = json.loads(user_message["content"])
        source = user["exp_source"]
        anchor = "mystery(3, 0x40, b'X')"
        start = source.find(anchor)
        result = {
            "source_hash": user["source_hash"],
            "proposals": [{
                "proposal_id": "helper-1",
                "action": "helper_mapping",
                "source_start": max(0, start),
                "source_end": max(0, start) + len(anchor),
                "source_text": anchor if start >= 0 else "",
                "ast_fingerprint": "",
                "confidence": 0.96,
                "rationale": "three roles are explicit",
                "operation": {},
                "helper_mapping": {"semantic": "alloc", "function": "mystery", "roles": ["index", "size", "data"], "arity": 3},
                "branch_choice": {},
                "memory_annotation": {},
                "rule": {},
            }],
            "diagnostics": [],
        }
        self._json(200, {"choices": [{"message": {"content": json.dumps(result)}}]})

    def _json(self, status: int, payload: dict):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class LocalAIIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LMStudioStub)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/v1"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _request(self, generation: int = 1) -> AIAnalysisRequest:
        source = "mystery(3, 0x40, b'X')\n"
        return AIAnalysisRequest.build(generation, source, {"arch": "amd64"}, {"valid": True, "operations": []})

    def test_v067_qwen_coder_defaults_and_prompt_budget(self) -> None:
        config = AIProviderConfig()
        self.assertEqual(config.model, "qwen3-coder-30b-a3b-instruct")
        self.assertEqual(config.analysis_mode, "manual")
        self.assertEqual(config.context_budget_tokens, 4096)
        self.assertEqual(config.max_input_tokens, 3584)
        self.assertEqual(config.max_tokens, 512)
        self.assertEqual(config.timeout, 180.0)
        self.assertTrue(config.json_prefill)

        small = PromptBudget.estimate("add(0x20, b'A')", config)
        self.assertTrue(small.fits)
        self.assertLessEqual(small.estimated_input_tokens, 3584)
        large = PromptBudget.estimate("堆" * 30000, config)
        self.assertFalse(large.fits)
        self.assertIn("超过当前可用", large.diagnostic)

    def test_prompt_budget_falls_back_to_lean_ir_without_truncating_exp(self) -> None:
        lines = [f"add(0x100, b'chunk-{index:02d}')" for index in range(80)]
        source = "\n".join(lines) + "\n"
        operations = []
        bindings = []
        cursor = 0
        for index, line in enumerate(lines, 1):
            operations.append({
                "kind": "alloc",
                "chunk": f"chunk_{index}",
                "index": index,
                "request_size": "0x100",
                "data": "p64(symbolic_value) + " + "b'A' * 0x100 " * 8,
            })
            bindings.append({
                "line": index,
                "start": cursor,
                "end": cursor + len(line),
                "confidence": "confirmed",
            })
            cursor += len(line) + 1
        request = AIAnalysisRequest.build(
            1,
            source,
            {"arch": "amd64"},
            {"valid": True, "operations": operations, "bindings": bindings},
        )
        config = AIProviderConfig(max_input_tokens=3584, max_tokens=512)
        normal = OpenAICompatibleProvider._messages(request, json_prefill=True)
        normal_budget = PromptBudget.estimate(
            json.dumps(normal, ensure_ascii=False, separators=(",", ":")),
            config,
        )
        messages, budget, compact = OpenAICompatibleProvider.prepare_messages(request, config)
        self.assertFalse(normal_budget.fits)
        self.assertTrue(compact)
        self.assertTrue(budget.fits)
        user_payload = json.loads(messages[1]["content"])
        self.assertEqual(user_payload["exp_source"], source)
        self.assertEqual(len(user_payload["static_analysis"]["timeline"]), 80)

    def test_over_budget_request_is_rejected_before_http_post(self) -> None:
        source = "add(0x20, b'A')\n" * 1000
        request = AIAnalysisRequest.build(1, source, {"arch": "amd64"}, {"operations": []})
        config = AIProviderConfig(
            self.base_url,
            "qwen-test",
            timeout=5,
            context_budget_tokens=4096,
            max_input_tokens=512,
            max_tokens=2048,
        )
        before = _LMStudioStub.post_count
        with self.assertRaises(ProviderError) as caught:
            OpenAICompatibleProvider(config).analyze(request)
        self.assertEqual(_LMStudioStub.post_count, before)
        self.assertIn("超过当前可用", str(caught.exception))

    def test_validator_caps_one_response_at_32_candidates(self) -> None:
        source = "mystery(1)\n"
        proposals = []
        for index in range(40):
            proposals.append({
                "proposal_id": f"helper-{index}",
                "action": "helper_mapping",
                "source_start": 0,
                "source_end": len(source.strip()),
                "source_text": source.strip(),
                "confidence": 0.8,
                "rationale": "bounded candidate",
                "helper_mapping": {
                    "semantic": "free",
                    "function": f"mystery_{index}",
                    "roles": ["index"],
                    "arity": 1,
                },
            })
        accepted, diagnostics = validate_ai_response(
            {"source_hash": "same", "proposals": proposals},
            source,
            "same",
        )
        self.assertEqual(len(accepted), 32)
        self.assertTrue(any("32" in item for item in diagnostics))

    def test_openai_compatible_provider_models_structured_and_fallback(self) -> None:
        config = AIProviderConfig(self.base_url, "qwen-test", api_token="local-secret", timeout=5)
        provider = OpenAICompatibleProvider(config)
        self.assertEqual(provider.list_models(), ("qwen-test",))
        self.assertEqual(_LMStudioStub.last_authorization, "Bearer local-secret")
        result = provider.analyze(self._request())
        self.assertEqual(result.proposals[0].action, "helper_mapping")
        self.assertEqual(result.proposals[0].helper_mapping["function"], "mystery")

        _LMStudioStub.reject_structured_once = True
        fallback = provider.analyze(self._request(2))
        self.assertTrue(any("structured output" in item for item in fallback.diagnostics))

    def test_validator_rejects_stale_and_untruthful_memory(self) -> None:
        source = "add(0x20, b'A')"
        proposals, diagnostics = validate_ai_response({"source_hash": "bad", "proposals": []}, source, "good")
        self.assertEqual(proposals, ())
        self.assertIn("source_hash", diagnostics[0])

        payload = {
            "source_hash": "good",
            "proposals": [{
                "proposal_id": "bad-memory",
                "action": "memory_annotation",
                "source_start": 0,
                "source_end": len(source),
                "source_text": source,
                "confidence": 1,
                "rationale": "invented",
                "memory_annotation": {"chunk": "A", "start": 0x10, "end": 0x20, "state": "zero", "provenance": "observed"},
            }],
        }
        proposals, diagnostics = validate_ai_response(payload, source, "good")
        self.assertEqual(proposals, ())
        self.assertTrue(any("provenance" in item or "zero" in item for item in diagnostics))

        unknown = {
            "source_hash": "good",
            "proposals": [{
                "proposal_id": "bad-field",
                "action": "replace_operation",
                "source_start": 0,
                "source_end": len(source),
                "source_text": source,
                "confidence": 0.8,
                "rationale": "unknown meta",
                "operation": {"kind": "alloc", "request_size": "0x20", "meta": {"execute_this": "no"}},
            }],
        }
        proposals, diagnostics = validate_ai_response(unknown, source, "good")
        self.assertEqual(proposals, ())
        self.assertTrue(any("未知字段" in item for item in diagnostics))

    def test_compact_wire_payload_expands_and_normalizes_helper_roles(self) -> None:
        compact = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "copy-map",
                "action": "helper_mapping",
                "source_start": 0,
                "source_end": 17,
                "source_text": "copy(src,dst,len)",
                "confidence": 0.9,
                "rationale": "verified",
                "payload_json": json.dumps({
                    "mapping": {
                        "semantic": "copy",
                        "function": "copy",
                        "roles": ["src", "dst", "len"],
                        "arity": 3,
                        "keywords": [],
                        "parameter_names": ["src", "dst", "len"],
                    },
                    "source_range": [0, 17],
                }),
            }],
            "diagnostics": [],
        }
        expanded = OpenAICompatibleProvider._expand_compact_proposals(compact)
        proposals, diagnostics = validate_ai_response(expanded, "copy(src,dst,len)", "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].helper_mapping["roles"], ["src", "dst", "length"])

    def test_compact_wire_payload_normalizes_qwen_role_objects(self) -> None:
        compact = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "free-map",
                "action": "helper_mapping",
                "source_start": 0,
                "source_end": 6,
                "source_text": "do4(0)",
                "confidence": 0.9,
                "rationale": "verified",
                "payload_json": json.dumps({
                    "semantic": "free",
                    "function": "do4",
                    "roles": ["{'name': 'index', 'value': 0}"],
                    "arity": 1,
                    "keywords": [],
                    "parameter_names": ["slot"],
                }),
            }],
            "diagnostics": [],
        }
        expanded = OpenAICompatibleProvider._expand_compact_proposals(compact)
        proposals, diagnostics = validate_ai_response(expanded, "do4(0)\n", "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].helper_mapping["roles"], ["index"])

    def test_minimal_static_prompt_dedupes_repeated_timeline_rows(self) -> None:
        raw = {
            "valid": True,
            "operations": [
                {"kind": "alloc"},
                {"kind": "free"},
                {"kind": "alloc"},
                {"kind": "free"},
            ],
            "bindings": [
                {"line": 10, "start": 100, "end": 110},
                {"line": 11, "start": 111, "end": 120},
                {"line": 10, "start": 100, "end": 110},
                {"line": 11, "start": 111, "end": 120},
            ],
        }
        compact = _compact_static_result(raw, lean=True, minimal=True)
        self.assertEqual(compact["timeline"], ["L10 alloc", "L11 free"])
        self.assertEqual(compact["timeline_repeats"], ["L10 alloc ×2", "L11 free ×2"])

    def test_qwen_coder_flat_dispatch_rule_is_normalized_and_validated(self) -> None:
        compact = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "cmd-copy",
                "action": "rule_candidate",
                "source_start": 0,
                "source_end": 0,
                "source_text": "cmd(7, src, dst, length)",
                "confidence": 0.95,
                "rationale": "reviewed dispatcher",
                "payload_json": json.dumps({
                    "rule_id": "cmd-copy",
                    "semantic": "copy",
                    "function": "cmd",
                    "argument_equals": [{"pos": 0, "value": 7}],
                    "roles": ["src", "dst", "length"],
                    "arg_offset": 1,
                    "enabled": True,
                }),
            }],
            "diagnostics": [],
        }
        expanded = OpenAICompatibleProvider._expand_compact_proposals(compact)
        proposals, diagnostics = validate_ai_response(expanded, "cmd(7, src, dst, length)\n", "same")
        self.assertFalse(diagnostics)
        rule = proposals[0].rule
        self.assertEqual(rule["matcher"]["argument_equals"], {"0": 7})
        self.assertEqual(rule["output"]["arg_offset"], 1)

    def test_qwen_heap_rule_call_compiles_to_a_valid_operation(self) -> None:
        source = "add(0x20, b'A')\nedit(0, b'B')\n"
        start = source.index("edit")
        compact = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "catalog-copy",
                "action": "heap_rule_call",
                "source_start": start,
                "source_end": len(source) - 1,
                "source_text": source[start:-1],
                "confidence": 0.95,
                "rationale": "copy helper semantics",
                "payload_json": json.dumps({
                    "rule_id": "op.copy",
                    "arguments": {"src": "0", "dst": "0", "length": "8"},
                }),
            }],
            "diagnostics": [],
        }
        expanded = OpenAICompatibleProvider._expand_compact_proposals(compact)
        proposals, diagnostics = validate_ai_response(expanded, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].action, "replace_operation")
        self.assertEqual(proposals[0].operation["kind"], "copy")
        self.assertEqual(proposals[0].operation["request_size"], "8")
        self.assertEqual(proposals[0].heap_rule_call["rule_id"], "op.copy")
        self.assertEqual(proposals[0].action, "replace_operation")

        compact["proposals"][0]["payload_json"] = json.dumps({
            "rule_id": "op.copy",
            "arguments": ["0", "1", "0x18"],
        })
        positional = OpenAICompatibleProvider._expand_compact_proposals(compact)
        proposals, diagnostics = validate_ai_response(positional, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].operation["target"], "0")
        self.assertEqual(proposals[0].operation["index"], "1")

        compact["proposals"][0]["payload_json"] = json.dumps({
            "rule_id": "corruption.fake_chunk",
            "arguments": {
                "chunk": "fake",
                "prev_size": 0,
                "size": "0x71",
                "fd": "fake",
                "bk": "target",
            },
        })
        corruption = OpenAICompatibleProvider._expand_compact_proposals(compact)
        proposals, diagnostics = validate_ai_response(corruption, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].action, "insert_after")
        self.assertEqual(proposals[0].operation["kind"], "fake_chunk")

        compact["proposals"][0]["payload_json"] = json.dumps({
            "rule_id": "corruption.fake_chunk",
            "placement": "execute_now",
            "arguments": {"chunk": "fake", "size": "0x71"},
        })
        invalid_placement = OpenAICompatibleProvider._expand_compact_proposals(compact)
        proposals, diagnostics = validate_ai_response(invalid_placement, source, "same")
        self.assertFalse(proposals)
        self.assertTrue(any("placement" in item for item in diagnostics))

    def test_qwen_miswrapped_heap_rule_operation_is_normalized(self) -> None:
        source = "add(0x68, payload)\n"
        encoded = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "bad-envelope",
                "action": "insert_after",
                "source_start": 0,
                "source_end": len(source) - 1,
                "source_text": source[:-1],
                "confidence": 0.95,
                "rationale": "local model used the operation envelope for a catalog call",
                "payload_json": json.dumps({
                    "operation": {
                        "rule_id": "op.alloc",
                        "arguments": {"chunk": "H", "index": 7, "request_size": "0x68"},
                    },
                }),
            }],
            "diagnostics": [],
        }
        expanded = OpenAICompatibleProvider._expand_compact_proposals(encoded)
        normalized = expanded["proposals"][0]
        self.assertEqual(normalized["action"], "heap_rule_call")
        self.assertEqual(normalized["operation"], {})
        self.assertEqual(normalized["heap_rule_call"]["placement"], "insert_after")
        proposals, diagnostics = validate_ai_response(expanded, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].action, "insert_after")
        self.assertEqual(proposals[0].operation["kind"], "alloc")
        self.assertEqual(proposals[0].operation["chunk"], "H")
        self.assertEqual(proposals[0].operation["request_size"], "0x68")

        direct = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "direct-bad-envelope",
                "action": "insert_after",
                "source_start": 0,
                "source_end": len(source) - 1,
                "source_text": source[:-1],
                "confidence": 0.95,
                "rationale": "same slip without payload_json",
                "operation": {
                    "rule_id": "op.free",
                    "arguments": {"chunk": "A"},
                },
            }],
            "diagnostics": [],
        }
        direct_expanded = OpenAICompatibleProvider._expand_compact_proposals(direct)
        proposals, diagnostics = validate_ai_response(direct_expanded, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].action, "insert_after")
        self.assertEqual(proposals[0].operation["kind"], "free")
        self.assertEqual(proposals[0].heap_rule_call["rule_id"], "op.free")

        catalog_slip = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "compact-catalog-slip",
                "action": "replace_operation",
                "source_start": 0,
                "source_end": len(source) - 1,
                "source_text": source[:-1],
                "confidence": 0.95,
                "rationale": "model copied compact catalog fields into operation",
                "operation": {
                    "id": "op.edit",
                    "args": {"index": 0, "size": 16, "data": "b'A'"},
                    "need": ["chunk|index"],
                },
            }],
            "diagnostics": [],
        }
        slipped = OpenAICompatibleProvider._expand_compact_proposals(catalog_slip)
        proposals, diagnostics = validate_ai_response(slipped, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].action, "replace_operation")
        self.assertEqual(proposals[0].operation["kind"], "edit")
        self.assertEqual(proposals[0].operation["request_size"], "16")

        nested_slip = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "nested-compact-catalog-slip",
                "action": "replace_operation",
                "source_start": 0,
                "source_end": len(source) - 1,
                "source_text": source[:-1],
                "confidence": 0.95,
                "rationale": "model nested catalog operation",
                "operation": {
                    "op": {
                        "type": "alloc",
                        "args": {"chunk": "A", "index": 0, "request_size": 256},
                    }
                },
            }],
            "diagnostics": [],
        }
        nested = OpenAICompatibleProvider._expand_compact_proposals(nested_slip)
        proposals, diagnostics = validate_ai_response(nested, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].operation["kind"], "alloc")
        self.assertEqual(proposals[0].operation["index"], "0")

    def test_qwen_timeline_span_anchor_rebinds_to_source_slice(self) -> None:
        source = "add(0x68, payload)\n"
        payload = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "timeline-anchor",
                "action": "heap_rule_call",
                "source_start": 1,
                "source_end": 2,
                "source_text": "1 L1@0:18 alloc chunk=A index=0 size=0x68",
                "confidence": 0.9,
                "rationale": "model copied the compact timeline row instead of the source slice",
                "heap_rule_call": {
                    "rule_id": "op.alloc",
                    "arguments": {"chunk": "A", "index": 0, "request_size": "0x68"},
                },
            }],
        }
        proposals, diagnostics = validate_ai_response(payload, source, "same")
        self.assertFalse(diagnostics)
        self.assertEqual(proposals[0].source_start, 0)
        self.assertEqual(proposals[0].source_end, 18)
        self.assertEqual(proposals[0].source_text, "add(0x68, payload)")
        self.assertEqual(proposals[0].operation["kind"], "alloc")

    def test_qwen_heap_rule_call_rejects_unknown_rules_and_arguments(self) -> None:
        source = "delete(0)\n"
        base = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "bad-catalog",
                "action": "heap_rule_call",
                "source_start": 0,
                "source_end": len(source) - 1,
                "source_text": source[:-1],
                "confidence": 0.9,
                "rationale": "bad rule",
                "heap_rule_call": {"rule_id": "op.shell", "arguments": {}},
            }],
        }
        proposals, diagnostics = validate_ai_response(base, source, "same")
        self.assertFalse(proposals)
        self.assertTrue(any("heap rule" in item for item in diagnostics))

    def test_validator_rejects_dispatcher_without_offset_and_named_role_conflict(self) -> None:
        source = "edit(0x20, payload)\n"
        bad_rule = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "bad-dispatch",
                "action": "rule_candidate",
                "source_start": 0,
                "source_end": 0,
                "source_text": "",
                "confidence": 0.9,
                "rationale": "missing offset",
                "rule": {
                    "rule_id": "bad",
                    "semantic": "alloc",
                    "matcher": {"function": "cmd", "argument_equals": {"0": 1}},
                    "output": {"roles": ["size", "index"]},
                },
            }],
        }
        proposals, diagnostics = validate_ai_response(bad_rule, source, "same")
        self.assertFalse(proposals)
        self.assertTrue(any("arg_offset" in item for item in diagnostics))

        bad_mapping = {
            "source_hash": "same",
            "proposals": [{
                "proposal_id": "bad-edit",
                "action": "helper_mapping",
                "source_start": 0,
                "source_end": len(source.strip()),
                "source_text": source.strip(),
                "confidence": 0.9,
                "rationale": "size is not an index",
                "helper_mapping": {
                    "semantic": "edit", "function": "edit",
                    "roles": ["index", "data"], "arity": 2,
                    "keywords": [], "parameter_names": ["size", "payload"],
                },
            }],
        }
        proposals, diagnostics = validate_ai_response(bad_mapping, source, "same")
        self.assertFalse(proposals)
        self.assertTrue(any("形参 `size`" in item for item in diagnostics))

    def test_provider_timeout_is_reported_without_sdk(self) -> None:
        provider = OpenAICompatibleProvider(AIProviderConfig(self.base_url, "qwen-test", timeout=1))
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with self.assertRaises(ProviderError) as caught:
                provider.list_models()
        self.assertIn("无法连接", str(caught.exception))

    def test_knowledge_feedback_rules_cache_and_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            proposal = AIProposal("p1", "helper_mapping", 0, 7, "take(x)", confidence=0.9, helper_mapping={"semantic": "free", "function": "take", "roles": ["index"]})
            stored = store.add_feedback(FeedbackRecord("", "hash", proposal.source_text, "rejected", proposal.to_dict()), proposal.signature())
            self.assertTrue(stored.feedback_id)
            self.assertTrue(store.is_rejected(proposal.signature()))
            self.assertEqual(store.retrieve_examples("take(7)")[0]["decision"], "rejected")

            rule = store.save_rule(LearnedRule("", "free", {"function": "take", "arity": 1}, {"roles": ["index"]}))
            self.assertTrue(rule.rule_id)
            self.assertEqual(store.list_rules()[0].semantic, "free")
            repeated = store.save_rule(rule)
            self.assertEqual(repeated.accept_count, 2)
            self.assertEqual(len(store.list_rules()), 1)
            store.set_rule_enabled(rule.rule_id, False)
            self.assertEqual(store.list_rules(), ())

            result = AIAnalysisResult(1, "hash", (proposal,), model="test")
            store.put_cached_result("cache", result)
            self.assertEqual(store.get_cached_result("cache").proposals[0].proposal_id, "p1")
            output = Path(directory) / "feedback.jsonl"
            self.assertEqual(store.export_jsonl(output), 1)
            self.assertIn('"decision": "rejected"', output.read_text(encoding="utf-8"))

    def test_unwritable_knowledge_path_falls_back_without_breaking_static_core(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            blocker = Path(directory) / "not-a-directory"
            blocker.write_text("x", encoding="utf-8")
            store = AIKnowledgeStore(blocker / "knowledge.sqlite3")
            self.assertFalse(store.persistent)
            self.assertTrue(store.degraded_reason)
            self.assertEqual(store.list_rules(), ())
            store.path.unlink(missing_ok=True)

    def test_coordinator_cache_and_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            coordinator = AIAnalysisCoordinator(store)
            first_generation = coordinator.next_generation()
            second_generation = coordinator.next_generation()
            self.assertFalse(coordinator.is_latest(first_generation))
            self.assertTrue(coordinator.is_latest(second_generation))
            config = AIProviderConfig(self.base_url, "qwen-test", timeout=5)
            request = self._request(second_generation)
            first = coordinator.analyze(OpenAICompatibleProvider(config), request, config)
            before = _LMStudioStub.post_count
            second = coordinator.analyze(OpenAICompatibleProvider(config), request, config)
            self.assertEqual(_LMStudioStub.post_count, before)
            self.assertTrue(second.cached)
            self.assertEqual(first.source_hash, second.source_hash)

            # The source can stay identical while branch/override/static IR
            # changes. Such a request must not hit the old response cache.
            changed = AIAnalysisRequest.build(
                second_generation,
                request.source,
                request.allocator,
                {"valid": True, "operations": [{"kind": "note"}]},
            )
            before_changed = _LMStudioStub.post_count
            coordinator.analyze(OpenAICompatibleProvider(config), changed, config)
            self.assertEqual(_LMStudioStub.post_count, before_changed + 1)

    def test_cached_result_is_filtered_after_negative_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            coordinator = AIAnalysisCoordinator(store)
            config = AIProviderConfig(self.base_url, "qwen-test", timeout=5)
            request = self._request(coordinator.next_generation())
            first = coordinator.analyze(OpenAICompatibleProvider(config), request, config)
            proposal = first.proposals[0]
            store.add_feedback(
                FeedbackRecord("", request.source_hash, proposal.source_text, "rejected", proposal.to_dict()),
                proposal.signature(),
            )
            cached = coordinator.analyze(OpenAICompatibleProvider(config), request, config)
            self.assertTrue(cached.cached)
            self.assertEqual(cached.proposals, ())
            self.assertTrue(any("缓存" in item for item in cached.diagnostics))

    def test_coordinator_offline_backoff_and_manual_recovery(self) -> None:
        class FailingProvider(LocalAIProvider):
            def health_check(self): return False, "offline"
            def list_models(self): return ()
            def analyze(self, _request):
                raise ProviderError("offline", kind="offline", retryable=True)

        class WorkingProvider(LocalAIProvider):
            def health_check(self): return True, "ok"
            def list_models(self): return ("test",)
            def analyze(self, request): return AIAnalysisResult(request.generation, request.source_hash, model="test")

        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            coordinator = AIAnalysisCoordinator(store)
            request = self._request(coordinator.next_generation())
            config = AIProviderConfig(self.base_url, "qwen-test", timeout=1)
            with self.assertRaises(ProviderError):
                coordinator.analyze(FailingProvider(), request, config)
            with self.assertRaises(ProviderError) as backed_off:
                coordinator.analyze(WorkingProvider(), request, config)
            self.assertIn("暂停重试", str(backed_off.exception))
            coordinator.reset_backoff()
            recovered = coordinator.analyze(WorkingProvider(), request, config)
            self.assertEqual(recovered.source_hash, request.source_hash)

    def test_non_retryable_budget_error_does_not_poison_next_case(self) -> None:
        class BudgetProvider(LocalAIProvider):
            def health_check(self): return True, "ok"
            def list_models(self): return ("test",)
            def analyze(self, _request):
                raise ProviderError("too large", kind="over_budget")

        class WorkingProvider(LocalAIProvider):
            def health_check(self): return True, "ok"
            def list_models(self): return ("test",)
            def analyze(self, request):
                return AIAnalysisResult(request.generation, request.source_hash, model="test")

        with tempfile.TemporaryDirectory() as directory:
            store = AIKnowledgeStore(Path(directory) / "knowledge.sqlite3")
            coordinator = AIAnalysisCoordinator(store)
            request = self._request(coordinator.next_generation())
            config = AIProviderConfig(self.base_url, "qwen-test", timeout=1)
            with self.assertRaises(ProviderError) as caught:
                coordinator.analyze(BudgetProvider(), request, config)
            self.assertEqual(caught.exception.kind, "over_budget")
            result = coordinator.analyze(WorkingProvider(), request, config)
            self.assertEqual(result.source_hash, request.source_hash)

    def test_exact_learned_rule_extends_static_analyzer(self) -> None:
        rule = LearnedRule(
            "rule1",
            "alloc",
            {"function": "mystery", "arity": 3},
            {"roles": ["index", "size", "data"]},
        ).to_dict()
        result = analyze_heap_source("mystery(3, 0x40, b'X')\n", learned_rules=[rule])
        self.assertEqual(len(result.operations), 1)
        self.assertEqual(result.operations[0].kind, HeapOperationKind.ALLOC)
        self.assertEqual((result.operations[0].index, result.operations[0].request_size), ("3", "0x40"))
        self.assertEqual(result.bindings[0].confidence, "learned")

    def test_learned_call_shape_does_not_cross_apply(self) -> None:
        from pwnbao.features.heapviz.analyzer import HeapSourceAnalyzer
        import ast

        call = next(node for node in ast.walk(ast.parse("mystery(3, 0x40, b'X')")) if isinstance(node, ast.Call))
        rule = LearnedRule(
            "rule-shape",
            "alloc",
            {
                "function": "mystery",
                "arity": 3,
                "call_shape": HeapSourceAnalyzer.learned_call_shape(call),
            },
            {"roles": ["index", "size", "data"]},
        ).to_dict()
        matched = analyze_heap_source("mystery(7, 0x80, b'Y')\n", learned_rules=[rule])
        self.assertEqual(len(matched.operations), 1)
        not_matched = analyze_heap_source("mystery(7, 0x80, flat(1, 2))\n", learned_rules=[rule])
        self.assertEqual(not_matched.operations, ())

    def test_learned_parameter_roles_support_reordered_keywords(self) -> None:
        rule = LearnedRule(
            "rule-keywords",
            "alloc",
            {
                "function": "mystery",
                "arity": 3,
                "keywords": ["x", "y", "z"],
                "parameter_names": ["x", "y", "z"],
            },
            {"roles": ["index", "size", "data"]},
        ).to_dict()
        result = analyze_heap_source("mystery(z=b'Z', x=5, y=0x90)\n", learned_rules=[rule])
        self.assertEqual(len(result.operations), 1)
        self.assertEqual(result.operations[0].index, "5")
        self.assertEqual(result.operations[0].request_size, "0x90")
        self.assertEqual(result.operations[0].data, "b'Z'")


if __name__ == "__main__":
    unittest.main()
