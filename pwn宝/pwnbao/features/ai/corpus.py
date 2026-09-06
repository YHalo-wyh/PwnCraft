from __future__ import annotations

import hashlib
import json
import time
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Iterable, Mapping

from pwnbao.features.heapviz import (
    GlibcHeapEngine,
    HeapAnalysisResult,
    HeapOperation,
    analyze_heap_source,
    build_allocator_config,
    diff_snapshot,
    parse_pwndbg_snapshot,
)

from .coordinator import AIAnalysisCoordinator
from .feedback_compiler import ProvenFeedbackCompiler
from .knowledge import AIKnowledgeStore
from .models import AIAnalysisRequest, AIProviderConfig
from .provider import LocalAIProvider, ProviderError
from .replay import StrictProposalReplayer


CORPUS_SCHEMA_VERSION = 1
ALLOWED_SPLITS = {"train", "dev", "holdout"}
ALLOWED_PURPOSES = {"semantic", "allocator_truth", "intent_only"}


@dataclass(frozen=True)
class CorpusAssertion:
    step: int
    field: str
    expected: object
    chunk: str = ""

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "CorpusAssertion":
        return cls(
            step=int(payload.get("step") or 0),
            field=str(payload.get("field") or ""),
            expected=payload.get("expected"),
            chunk=str(payload.get("chunk") or ""),
        )


@dataclass(frozen=True)
class CorpusCase:
    case_id: str
    split: str
    technique: str
    source_uri: str
    source_hash: str
    source_language: str = "python"
    purpose: str = "semantic"
    license: str = ""
    allocator: dict[str, object] = field(default_factory=dict)
    expected_ir: tuple[dict[str, object], ...] = ()
    operations: tuple[dict[str, object], ...] = ()
    assertions: tuple[CorpusAssertion, ...] = ()
    pwndbg_uri: str = ""
    pwndbg_hash: str = ""
    note: str = ""

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "CorpusCase":
        case = cls(
            case_id=str(payload.get("case_id") or "").strip(),
            split=str(payload.get("split") or "").strip(),
            technique=str(payload.get("technique") or "").strip(),
            source_uri=str(payload.get("source_uri") or "").strip(),
            source_hash=str(payload.get("source_hash") or "").strip().lower(),
            source_language=str(payload.get("source_language") or "python").strip().lower(),
            purpose=str(payload.get("purpose") or "semantic").strip(),
            license=str(payload.get("license") or "").strip(),
            allocator=dict(payload.get("allocator") or {}),
            expected_ir=tuple(dict(item) for item in list(payload.get("expected_ir") or []) if isinstance(item, Mapping)),
            operations=tuple(dict(item) for item in list(payload.get("operations") or []) if isinstance(item, Mapping)),
            assertions=tuple(
                CorpusAssertion.from_dict(item)
                for item in list(payload.get("assertions") or [])
                if isinstance(item, Mapping)
            ),
            pwndbg_uri=str(payload.get("pwndbg_uri") or "").strip(),
            pwndbg_hash=str(payload.get("pwndbg_hash") or "").strip().lower(),
            note=str(payload.get("note") or "").strip(),
        )
        case.validate()
        return case

    def validate(self) -> None:
        import re

        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.case_id):
            raise ValueError(f"invalid corpus case_id `{self.case_id}`")
        if self.split not in ALLOWED_SPLITS:
            raise ValueError(f"{self.case_id}: split must be train/dev/holdout")
        if not self.technique or len(self.technique) > 128:
            raise ValueError(f"{self.case_id}: invalid technique")
        if not re.fullmatch(r"[0-9a-f]{64}", self.source_hash):
            raise ValueError(f"{self.case_id}: source_hash must be SHA256")
        if self.source_language not in {"python", "c"}:
            raise ValueError(f"{self.case_id}: source_language must be python/c")
        if self.purpose not in ALLOWED_PURPOSES:
            raise ValueError(f"{self.case_id}: invalid purpose")
        if self.purpose == "semantic" and self.source_language != "python":
            raise ValueError(f"{self.case_id}: semantic corpus requires Python source")
        if not self.source_uri:
            raise ValueError(f"{self.case_id}: missing source_uri")
        if self.pwndbg_uri and not re.fullmatch(r"[0-9a-f]{64}", self.pwndbg_hash):
            raise ValueError(f"{self.case_id}: pwndbg_hash must be SHA256 when pwndbg_uri is set")

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "split": self.split,
            "technique": self.technique,
            "source_uri": self.source_uri,
            "source_hash": self.source_hash,
            "source_language": self.source_language,
            "purpose": self.purpose,
            "license": self.license,
            "allocator": dict(self.allocator),
            "expected_ir": [dict(item) for item in self.expected_ir],
            "operations": [dict(item) for item in self.operations],
            "assertions": [asdict(item) for item in self.assertions],
            "pwndbg_uri": self.pwndbg_uri,
            "pwndbg_hash": self.pwndbg_hash,
            "note": self.note,
        }


@dataclass(frozen=True)
class CorpusManifest:
    cases: tuple[CorpusCase, ...]
    source_path: Path
    schema_version: int = CORPUS_SCHEMA_VERSION

    @classmethod
    def load(cls, path: str | Path) -> "CorpusManifest":
        source_path = Path(path).resolve()
        raw = json.loads(source_path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError("corpus manifest root must be an object")
        version = int(raw.get("schema_version") or 0)
        if version != CORPUS_SCHEMA_VERSION:
            raise ValueError(f"unsupported corpus schema {version}")
        cases = tuple(CorpusCase.from_dict(item) for item in list(raw.get("cases") or []) if isinstance(item, Mapping))
        if not cases:
            raise ValueError("corpus manifest contains no cases")
        ids = [item.case_id for item in cases]
        if len(ids) != len(set(ids)):
            raise ValueError("corpus case_id must be unique")
        technique_splits: dict[str, str] = {}
        for case in cases:
            previous = technique_splits.setdefault(case.technique, case.split)
            if previous != case.split:
                raise ValueError(
                    f"technique `{case.technique}` crosses {previous}/{case.split}; split by technique to prevent leakage"
                )
        return cls(cases, source_path, version)


def resolve_case_source(
    case: CorpusCase,
    manifest_path: str | Path,
    cache_dir: str | Path,
    *,
    allow_network: bool = False,
) -> tuple[str, Path]:
    uri = case.source_uri
    cache_root = Path(cache_dir)
    if uri.startswith(("https://", "http://")):
        suffix = Path(uri.split("?", 1)[0]).suffix or (".py" if case.source_language == "python" else ".c")
        source_path = cache_root / "sources" / f"{case.source_hash}{suffix}"
        if not source_path.exists():
            if not allow_network:
                raise FileNotFoundError(f"{case.case_id}: public source is not cached; rerun with --allow-network")
            source_path.parent.mkdir(parents=True, exist_ok=True)
            request = urllib.request.Request(uri, headers={"User-Agent": "pwnbao-heap-corpus/1"})
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError(f"{case.case_id}: source exceeds 4 MiB")
            if hashlib.sha256(data).hexdigest() != case.source_hash:
                raise ValueError(f"{case.case_id}: downloaded SHA256 mismatch")
            source_path.write_bytes(data)
    else:
        candidate = Path(uri)
        if not candidate.is_absolute():
            candidate = Path(manifest_path).resolve().parent / candidate
        source_path = candidate.resolve()
    data = source_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != case.source_hash:
        raise ValueError(f"{case.case_id}: source SHA256 mismatch ({digest})")
    return data.decode("utf-8", errors="replace"), source_path


def analysis_payload(result: HeapAnalysisResult) -> dict[str, object]:
    return {
        "valid": result.valid,
        "operations": [item.to_dict() for item in result.operations],
        "bindings": [
            {
                "source_id": item.source_id,
                "start": item.start,
                "end": item.end,
                "line": item.line,
                "end_line": item.end_line,
                "fingerprint": item.fingerprint,
                "loop_env": list(item.loop_env),
                "confidence": item.confidence,
                "match_status": item.match_status,
            }
            for item in result.bindings
        ],
        "branches": [asdict(item) for item in result.branch_groups],
        "diagnostics": [asdict(item) for item in result.diagnostics],
        "symbols": dict(result.symbols),
    }


def snapshot_payload(snapshot) -> dict[str, object]:
    return {
        "step": snapshot.step,
        "aborted": snapshot.aborted,
        "chunks": {
            chunk_id: {
                "address": chunk.address,
                "user_address": chunk.user_address,
                "chunk_size": chunk.chunk_size,
                "lifecycle": chunk.lifecycle,
                "bin_location": chunk.bin_location,
                "fd": chunk.fd,
                "bk": chunk.bk,
                "provenance": chunk.provenance,
            }
            for chunk_id, chunk in snapshot.chunks.items()
        },
        "bins": asdict(snapshot.bins),
        "warnings": [asdict(item) for item in snapshot.warnings],
    }


def observed_payload(observed) -> dict[str, object]:
    return {
        "bins": {
            name: {hex(size): [hex(address) for address in addresses] for size, addresses in mapping.items()}
            for name, mapping in observed.bins.items()
        },
        "chunks": [asdict(item) for item in observed.chunks],
        "raw_sections": list(observed.raw_sections),
    }


class CorpusEvaluator:
    def __init__(
        self,
        knowledge: AIKnowledgeStore,
        config: AIProviderConfig | None = None,
        provider: LocalAIProvider | None = None,
    ):
        self.knowledge = knowledge
        self.config = config or AIProviderConfig()
        self.provider = provider
        self.coordinator = AIAnalysisCoordinator(knowledge)
        self.feedback_compiler = ProvenFeedbackCompiler(knowledge)

    def run(
        self,
        manifest: CorpusManifest,
        output_dir: str | Path,
        *,
        allow_network: bool = False,
        use_ai: bool = False,
        resume: bool = True,
        splits: Iterable[str] = ALLOWED_SPLITS,
        case_ids: Iterable[str] | None = None,
        auto_review_proven: bool = False,
        promotion_mode: str = "strict",
        promote_threshold: int | None = None,
        promote_without_holdout: bool = False,
        promotion_confidence: float | None = None,
    ) -> dict[str, object]:
        output_root = Path(output_dir)
        output_root.mkdir(parents=True, exist_ok=True)
        enabled_splits = set(splits)
        enabled_cases = {str(item) for item in case_ids or ()}
        promotion_policy = ProvenFeedbackCompiler._promotion_policy(
            promotion_mode,
            minimum_positive_cases=promote_threshold,
            require_holdout=False if promote_without_holdout else None,
            confidence_threshold=promotion_confidence,
        )
        summaries: list[dict[str, object]] = []
        evaluated_payloads: list[dict[str, object]] = []
        for case in manifest.cases:
            if case.split not in enabled_splits:
                continue
            if enabled_cases and case.case_id not in enabled_cases:
                continue
            target = output_root / f"{case.case_id}.json"
            if resume and target.exists():
                try:
                    cached = json.loads(target.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    cached = {}
                if cached.get("source_hash") == case.source_hash and cached.get("status") == "completed":
                    summaries.append({"case_id": case.case_id, "status": "cached", "artifact": str(target)})
                    evaluated_payloads.append(cached)
                    continue
            result = self.evaluate_case(
                case,
                manifest.source_path,
                output_root,
                allow_network=allow_network,
                use_ai=use_ai,
                auto_review_proven=auto_review_proven,
                promotion_mode=str(promotion_policy["mode"]),
                promote_threshold=int(promotion_policy["minimum_positive_cases"]),
                require_holdout=bool(promotion_policy["require_holdout"]),
                promotion_confidence=float(promotion_policy["confidence_threshold"]),
            )
            temporary = target.with_suffix(target.suffix + ".tmp")
            temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(target)
            summaries.append({"case_id": case.case_id, "status": result["status"], "artifact": str(target)})
            evaluated_payloads.append(result)
        gap_report = self._gap_report(manifest, evaluated_payloads, promotion_policy)
        (output_root / "gap_report.json").write_text(
            json.dumps(gap_report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        learning_report = self._learning_report(manifest, evaluated_payloads, promotion_policy)
        (output_root / "aggressive_learning_report.json").write_text(
            json.dumps(learning_report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        summary = {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "model": self.config.model if use_ai else "static-only",
            "cases": summaries,
            "completed": sum(1 for item in summaries if item["status"] in {"completed", "cached"}),
            "failed": sum(1 for item in summaries if item["status"] not in {"completed", "cached"}),
            "gap_report": str(output_root / "gap_report.json"),
            "learning_report": str(output_root / "aggressive_learning_report.json"),
            "promotion_policy": promotion_policy,
        }
        (output_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return summary

    @staticmethod
    def _gap_report(
        manifest: CorpusManifest,
        payloads: list[dict[str, object]],
        promotion_policy: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        cases_by_id = {item.case_id: item for item in manifest.cases}
        counts: dict[str, int] = {}
        examples: dict[str, list[str]] = {}

        def add(code: str, case_id: str) -> None:
            counts[code] = counts.get(code, 0) + 1
            bucket = examples.setdefault(code, [])
            if case_id not in bucket and len(bucket) < 8:
                bucket.append(case_id)

        for payload in payloads:
            case_id = str(payload.get("case_id") or "")
            case = cases_by_id.get(case_id)
            if payload.get("status") not in {"completed", "cached"}:
                add("run_" + str(payload.get("status") or "failed"), case_id)
                continue
            if case and case.purpose == "intent_only":
                add("intent_only_not_allocator_fact", case_id)
            if case and case.purpose == "allocator_truth" and not case.operations and not case.assertions:
                add("allocator_oracle_review_required", case_id)
            static = dict(payload.get("static") or {})
            for diagnostic in list(static.get("diagnostics") or []):
                if isinstance(diagnostic, Mapping):
                    add("static_" + str(diagnostic.get("code") or "diagnostic"), case_id)
            failed_assertions = [item for item in list(payload.get("assertions") or []) if isinstance(item, Mapping) and not item.get("ok")]
            for _item in failed_assertions:
                add("allocator_truth_mismatch", case_id)
            if case and case.purpose == "semantic" and not case.expected_ir:
                add("golden_ir_review_required", case_id)
        return {
            "counts": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
            "examples": examples,
            "promotion_policy": dict(promotion_policy or {
                "minimum_independent_cases": 2,
                "requires_zero_rejected_cases": True,
                "requires_holdout": True,
            }),
        }

    @staticmethod
    def _learning_report(
        manifest: CorpusManifest,
        payloads: list[dict[str, object]],
        promotion_policy: Mapping[str, object],
    ) -> dict[str, object]:
        cases_by_id = {item.case_id: item for item in manifest.cases}
        counters = {
            "cases": 0,
            "completed_or_cached": 0,
            "strict_preview_accepted": 0,
            "strict_preview_rejected": 0,
            "feedback_compiled": 0,
            "rules_enabled": 0,
            "rules_pending": 0,
            "over_budget": 0,
            "offline_or_model": 0,
            "failed": 0,
        }
        examples: list[dict[str, object]] = []
        blocked: dict[str, int] = {}

        def bump_blocked(reason: str) -> None:
            blocked[reason] = blocked.get(reason, 0) + 1

        for payload in payloads:
            case_id = str(payload.get("case_id") or "")
            case = cases_by_id.get(case_id)
            status = str(payload.get("status") or "")
            counters["cases"] += 1
            if status in {"completed", "cached"}:
                counters["completed_or_cached"] += 1
            elif status == "over_budget":
                counters["over_budget"] += 1
                bump_blocked("over_budget")
            elif status in {"offline", "model", "response"}:
                counters["offline_or_model"] += 1
                bump_blocked(status)
            else:
                counters["failed"] += 1
                bump_blocked(status or "failed")

            previews = [item for item in list(payload.get("strict_previews") or []) if isinstance(item, Mapping)]
            for index, preview in enumerate(previews):
                if preview.get("accepted"):
                    counters["strict_preview_accepted"] += 1
                else:
                    counters["strict_preview_rejected"] += 1
                    bump_blocked("strict_replay_rejected")
                if len(examples) < 24:
                    examples.append({
                        "case_id": case_id,
                        "technique": case.technique if case else "",
                        "kind": "strict_preview",
                        "index": index,
                        "accepted": bool(preview.get("accepted")),
                        "message": str(preview.get("message") or ""),
                        "semantic_changed": bool(preview.get("semantic_changed")),
                    })

            compilations = [
                item for item in list(payload.get("feedback_compilation") or []) if isinstance(item, Mapping)
            ]
            for item in compilations:
                if item.get("accepted"):
                    counters["feedback_compiled"] += 1
                else:
                    bump_blocked(str(item.get("message") or "feedback_not_compiled"))
                if item.get("rule_enabled"):
                    counters["rules_enabled"] += 1
                elif item.get("rule_id"):
                    counters["rules_pending"] += 1
                    promotion = dict(item.get("promotion") or {})
                    for reason in list(promotion.get("blocked_by") or []):
                        bump_blocked("promotion_" + str(reason))
                if len(examples) < 24:
                    examples.append({
                        "case_id": case_id,
                        "technique": case.technique if case else "",
                        "kind": "feedback_compilation",
                        "accepted": bool(item.get("accepted")),
                        "rule_enabled": bool(item.get("rule_enabled")),
                        "message": str(item.get("message") or ""),
                        "promotion": dict(item.get("promotion") or {}),
                    })

        return {
            "schema_version": CORPUS_SCHEMA_VERSION,
            "promotion_policy": dict(promotion_policy),
            "counters": counters,
            "blocked_reasons": dict(sorted(blocked.items(), key=lambda item: (-item[1], item[0]))),
            "examples": examples,
            "note": (
                "只有 strict replay accepted 的候选会进入规则审核；rejected/over_budget 只作为负反馈、提示词和静态分析 gap，"
                "不会直接改 chunk/bin/画布事实。"
            ),
        }

    def evaluate_case(
        self,
        case: CorpusCase,
        manifest_path: str | Path,
        output_root: str | Path,
        *,
        allow_network: bool,
        use_ai: bool,
        auto_review_proven: bool = False,
        promotion_mode: str = "strict",
        promote_threshold: int | None = None,
        require_holdout: bool | None = None,
        promotion_confidence: float | None = None,
    ) -> dict[str, object]:
        started = time.monotonic()
        self.knowledge.upsert_corpus_case(case.to_dict())
        promotion_policy = ProvenFeedbackCompiler._promotion_policy(
            promotion_mode,
            minimum_positive_cases=promote_threshold,
            require_holdout=require_holdout,
            confidence_threshold=promotion_confidence,
        )
        run_id = "run_" + uuid.uuid4().hex
        base = {
            "run_id": run_id,
            "case_id": case.case_id,
            "source_hash": case.source_hash,
            "model": self.config.model if use_ai else "static-only",
            "prompt_version": "",
        }
        try:
            source, source_path = resolve_case_source(case, manifest_path, output_root, allow_network=allow_network)
            analysis = analyze_heap_source(source) if case.source_language == "python" else HeapAnalysisResult()
            if case.operations:
                operations = [HeapOperation.from_dict(item) for item in case.operations]
            else:
                operations = list(analysis.operations)
            version = str(case.allocator.get("version") or "2.35")
            arch = str(case.allocator.get("arch") or "amd64")
            config = build_allocator_config(arch, f"glibc {version}")
            snapshots = GlibcHeapEngine(config).replay(operations)
            assertion_results = self._check_assertions(case, snapshots)
            metrics = self._metrics(case, analysis, assertion_results)
            observed = None
            observed_diff = None
            if case.pwndbg_uri:
                observed_case = replace(
                    case,
                    source_uri=case.pwndbg_uri,
                    source_hash=case.pwndbg_hash,
                    source_language="python",
                    purpose="allocator_truth",
                    pwndbg_uri="",
                    pwndbg_hash="",
                )
                observed_text, _ = resolve_case_source(observed_case, manifest_path, output_root, allow_network=allow_network)
                observed = parse_pwndbg_snapshot(observed_text)
                observed_diff = diff_snapshot(snapshots[-1], observed)
            ai_result: dict[str, object] = {}
            ai_previews: list[dict[str, object]] = []
            feedback_compilation: list[dict[str, object]] = []
            status = "completed"
            if use_ai and case.purpose == "semantic":
                if self.provider is None:
                    raise ProviderError("Qwen provider is not configured")
                generation = self.coordinator.next_generation()
                request = AIAnalysisRequest.build(
                    generation,
                    source,
                    {"family": "glibc", "version": version, "arch": arch, "safe_linking": config.safe_linking},
                    analysis_payload(analysis),
                    instruction=(
                        "只校正能由源码、严格 allocator 或随请求提供的 Pwndbg 证据证明的 Heap IR。"
                        "不要直接修改画布，不要把利用意图当作 allocator 事实。"
                    ),
                    current_snapshot=snapshot_payload(snapshots[-1]),
                    observed_heap=observed_payload(observed) if observed else {},
                    observed_diff={
                        "matched": observed_diff.matched,
                        "mismatched": observed_diff.mismatched,
                        "unknown": observed_diff.unknown,
                        "lines": list(observed_diff.lines),
                    } if observed_diff else {},
                )
                result = self.coordinator.analyze(self.provider, request, self.config)
                ai_result = result.to_dict()
                replayer = StrictProposalReplayer(
                    source,
                    analysis,
                    config,
                    observed=observed,
                    learned_rules=(item.to_dict() for item in self.knowledge.list_rules()),
                )
                preview_results = [replayer.preview(item) for item in result.proposals]
                ai_previews = [item.to_dict() for item in preview_results]
                if auto_review_proven:
                    feedback_compilation = [
                        self.feedback_compiler.compile(
                            case_id=case.case_id,
                            run_id=run_id,
                            source=source,
                            source_hash=case.source_hash,
                            proposal=proposal,
                            replay=preview,
                            model=result.model,
                            prompt_version=result.prompt_version,
                            holdout_passed=case.split == "holdout",
                            promotion_mode=str(promotion_policy["mode"]),
                            minimum_positive_cases=int(promotion_policy["minimum_positive_cases"]),
                            require_holdout=bool(promotion_policy["require_holdout"]),
                            confidence_threshold=float(promotion_policy["confidence_threshold"]),
                        ).to_dict()
                        for proposal, preview in zip(result.proposals, preview_results)
                    ]
                base["prompt_version"] = result.prompt_version
                metrics["ai_candidates"] = len(ai_previews)
                metrics["ai_raw_candidates"] = len(result.candidate_audit)
                metrics["ai_validator_rejected"] = max(0, len(result.candidate_audit) - len(result.proposals))
                metrics["ai_replay_accepted"] = sum(bool(item["accepted"]) for item in ai_previews)
                metrics["ai_replay_rejected"] = sum(not bool(item["accepted"]) for item in ai_previews)
            payload = {
                **base,
                "status": status,
                "source_path": str(source_path),
                "purpose": case.purpose,
                "static": analysis_payload(analysis),
                "snapshot": snapshot_payload(snapshots[-1]),
                "assertions": assertion_results,
                "metrics": metrics,
                "ai": ai_result,
                "strict_previews": ai_previews,
                "feedback_compilation": feedback_compilation,
                "promotion_policy": promotion_policy,
                "elapsed_s": round(time.monotonic() - started, 3),
            }
        except ProviderError as error:
            payload = {
                **base,
                "status": error.kind,
                "error": str(error),
                "retryable": error.retryable,
                "details": error.details,
                "elapsed_s": round(time.monotonic() - started, 3),
            }
        except Exception as error:
            payload = {
                **base,
                "status": "failed",
                "error": f"{type(error).__name__}: {error}",
                "elapsed_s": round(time.monotonic() - started, 3),
            }
        self.knowledge.save_evaluation_run({
            **base,
            "status": payload["status"],
            "metrics": dict(payload.get("metrics") or {}),
            "result": payload,
        })
        return payload

    @staticmethod
    def _check_assertions(case: CorpusCase, snapshots) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for assertion in case.assertions:
            actual: object = None
            error = ""
            if not 0 <= assertion.step < len(snapshots):
                error = "step out of range"
            else:
                snapshot = snapshots[assertion.step]
                if assertion.field == "aborted":
                    actual = snapshot.aborted
                elif assertion.chunk not in snapshot.chunks:
                    error = "chunk not found"
                else:
                    chunk = snapshot.chunks[assertion.chunk]
                    actual = getattr(chunk, assertion.field, None)
            result.append({
                **asdict(assertion),
                "actual": actual,
                "ok": not error and str(actual) == str(assertion.expected),
                "error": error,
            })
        return result

    @staticmethod
    def _metrics(case: CorpusCase, analysis: HeapAnalysisResult, assertions: list[dict[str, object]]) -> dict[str, object]:
        expected = list(case.expected_ir)
        actual = [item.to_dict() for item in analysis.operations]
        comparable = min(len(expected), len(actual))
        semantic_matches = sum(
            1 for index in range(comparable)
            if str(expected[index].get("kind") or "") == str(actual[index].get("kind") or "")
        )
        return {
            "operation_count": len(actual),
            "expected_operation_count": len(expected),
            "semantic_exact": semantic_matches,
            "semantic_total": max(len(expected), len(actual)),
            "assertions_passed": sum(1 for item in assertions if item["ok"]),
            "assertions_total": len(assertions),
            "static_valid": analysis.valid,
        }
