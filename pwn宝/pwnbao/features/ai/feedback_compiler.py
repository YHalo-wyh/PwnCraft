from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import asdict, dataclass, replace

from pwnbao.features.heapviz.analyzer import HeapSourceAnalyzer

from .knowledge import AIKnowledgeStore
from .models import AIProposal, FeedbackRecord, LearnedRule
from .replay import ProposalReplayResult


@dataclass(frozen=True)
class FeedbackCompileResult:
    accepted: bool
    message: str
    feedback_id: str = ""
    fixture_id: str = ""
    rule_id: str = ""
    rule_enabled: bool = False
    promotion: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class ProvenFeedbackCompiler:
    """Compile strictly replayed AI feedback into deterministic static assets."""

    def __init__(self, knowledge: AIKnowledgeStore):
        self.knowledge = knowledge

    def compile(
        self,
        *,
        case_id: str,
        run_id: str,
        source: str,
        source_hash: str,
        proposal: AIProposal,
        replay: ProposalReplayResult,
        model: str,
        prompt_version: str,
        holdout_passed: bool = False,
        promotion_mode: str = "strict",
        minimum_positive_cases: int | None = None,
        require_holdout: bool | None = None,
        confidence_threshold: float | None = None,
    ) -> FeedbackCompileResult:
        policy = self._promotion_policy(
            promotion_mode,
            minimum_positive_cases=minimum_positive_cases,
            require_holdout=require_holdout,
            confidence_threshold=confidence_threshold,
        )
        if not replay.accepted:
            return FeedbackCompileResult(False, "strict replay rejected")
        if proposal.confidence < policy["confidence_threshold"]:
            return FeedbackCompileResult(False, f"confidence below {policy['confidence_threshold']:.2f}")
        digest = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()
        if digest != source_hash:
            return FeedbackCompileResult(False, "source hash mismatch")
        if proposal.source_text and source[proposal.source_start:proposal.source_end] != proposal.source_text:
            return FeedbackCompileResult(False, "source anchor mismatch")

        feedback = self.knowledge.add_feedback(
            FeedbackRecord(
                "",
                source_hash,
                proposal.source_text,
                "accepted",
                proposal.to_dict(),
                replay.to_dict(),
                model,
                prompt_version,
            ),
            proposal.signature(),
        )
        fixture = self.knowledge.add_regression_fixture(
            feedback_id=feedback.feedback_id,
            source_hash=source_hash,
            category="heap_rule_call" if proposal.heap_rule_call else proposal.action,
            source_fragment=proposal.source_text,
            expected={
                "proposal": proposal.to_dict(),
                "replay": replay.to_dict(),
            },
        )
        if proposal.snapshot_effect:
            self.knowledge.add_snapshot_review({
                "case_id": case_id,
                "run_id": run_id,
                "proposal_signature": proposal.signature(),
                "decision": "accepted",
                "effect": proposal.snapshot_effect,
                "evidence": list(proposal.snapshot_effect.get("evidence") or []),
            })

        learned = self._learned_rule(source, proposal, replay)
        if learned is None:
            return FeedbackCompileResult(
                True,
                "fixture stored; proposal does not safely compile to a basic helper rule",
                feedback.feedback_id,
                str(fixture["fixture_id"]),
            )
        canonical = replace(self._canonicalize_rule(learned), source=str(policy["rule_source"]))
        stored, promotion = self.knowledge.review_rule_candidate(
            canonical,
            case_id=case_id,
            feedback_id=feedback.feedback_id,
            decision="accepted",
            holdout_passed=holdout_passed,
            minimum_positive_cases=int(policy["minimum_positive_cases"]),
            require_holdout=bool(policy["require_holdout"]),
            maximum_rejected_cases=0,
        )
        return FeedbackCompileResult(
            True,
            "rule enabled" if stored.enabled else "rule pending independent-case/holdout evidence",
            feedback.feedback_id,
            str(fixture["fixture_id"]),
            stored.rule_id,
            stored.enabled,
            promotion,
        )

    @staticmethod
    def _promotion_policy(
        promotion_mode: str,
        *,
        minimum_positive_cases: int | None = None,
        require_holdout: bool | None = None,
        confidence_threshold: float | None = None,
    ) -> dict[str, object]:
        mode = str(promotion_mode or "strict").strip().lower().replace("-", "_")
        if mode not in {"strict", "aggressive", "global_now"}:
            raise ValueError("promotion_mode must be strict/aggressive/global_now")
        default_cases = 2 if mode == "strict" else 1
        default_holdout = mode == "strict"
        default_confidence = 0.9 if mode == "strict" else (0.8 if mode == "aggressive" else 0.7)
        threshold = default_cases if minimum_positive_cases is None else max(1, int(minimum_positive_cases))
        holdout = default_holdout if require_holdout is None else bool(require_holdout)
        confidence = default_confidence if confidence_threshold is None else float(confidence_threshold)
        return {
            "mode": mode,
            "minimum_positive_cases": threshold,
            "require_holdout": holdout,
            "confidence_threshold": max(0.0, min(1.0, confidence)),
            "maximum_rejected_cases": 0,
            "rule_source": "qwen-strict-auto" if mode == "strict" else f"qwen-strict-auto:{mode}",
        }

    def _learned_rule(
        self,
        source: str,
        proposal: AIProposal,
        replay: ProposalReplayResult,
    ) -> LearnedRule | None:
        if replay.learned_rule:
            return LearnedRule.from_dict(replay.learned_rule)
        if not proposal.heap_rule_call:
            return None
        kind = str(proposal.operation.get("kind") or "")
        if kind not in {"alloc", "free", "edit", "show", "copy"}:
            return None
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        call = self._anchored_call(proposal.source_text)
        if call is None:
            return None
        function = HeapSourceAnalyzer._call_name(call.func)
        definition = next(
            (
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function
            ),
            None,
        )
        if definition is None:
            return None
        parameters = [
            item.arg
            for item in (*definition.args.posonlyargs, *definition.args.args, *definition.args.kwonlyargs)
        ]
        roles = [self._parameter_role(name, kind) for name in parameters]
        if not roles or any(not role for role in roles):
            return None
        return LearnedRule(
            "",
            kind,
            {
                "function": function,
                "arity": len(parameters),
                "keywords": [str(item.arg) for item in call.keywords if item.arg],
                "parameter_names": parameters,
                "call_shape": HeapSourceAnalyzer.learned_call_shape(call),
            },
            {"roles": roles},
            enabled=False,
            source="qwen-strict-auto",
        )

    @staticmethod
    def _anchored_call(source_text: str) -> ast.Call | None:
        try:
            tree = ast.parse(source_text)
        except SyntaxError:
            return None
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        if not calls:
            return None
        return min(calls, key=lambda node: (getattr(node, "col_offset", 0), getattr(node, "lineno", 0)))

    @staticmethod
    def _parameter_role(name: str, semantic: str) -> str:
        key = name.lower().strip("_")
        if semantic == "copy":
            if key in {"src", "source", "from_idx", "src_idx"}:
                return "src"
            if key in {"dst", "dest", "destination", "to_idx", "dst_idx"}:
                return "dst"
            if key in {"length", "len", "n", "size", "count"}:
                return "length"
        if key in {"idx", "index", "i", "id", "sid", "uid", "no", "num", "slot", "pos", "key"}:
            return "index"
        if key in {"size", "sz", "length", "len", "n", "request", "request_size", "chunk_size"}:
            return "size"
        if key in {"data", "content", "contents", "payload", "text", "msg", "buf", "blob", "body", "buffer", "name", "value"}:
            return "data"
        return ""

    @staticmethod
    def _canonicalize_rule(rule: LearnedRule) -> LearnedRule:
        identity = json.dumps(
            {
                "semantic": rule.semantic,
                "matcher": rule.matcher,
                "output": rule.output,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        rule_id = "rule_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        return replace(rule, rule_id=rule_id, enabled=False)
