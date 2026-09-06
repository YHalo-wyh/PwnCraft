from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import tempfile
import threading
import uuid
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .models import AIAnalysisResult, FeedbackRecord, LearnedRule


def default_knowledge_path() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "pwnbao" / "ai" / "knowledge.sqlite3"
    return Path.home() / ".local" / "share" / "pwnbao" / "ai" / "knowledge.sqlite3"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AIKnowledgeStore:
    SCHEMA_VERSION = 2

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = Path(path) if path else default_knowledge_path()
        self._lock = threading.RLock()
        self.persistent = True
        self.degraded_reason = ""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()
        except (OSError, sqlite3.Error) as error:
            # Knowledge persistence is optional. A locked/corrupt/unwritable
            # database must never prevent the deterministic AST/allocator UI
            # from starting, so keep a per-process fallback store.
            self.persistent = False
            self.degraded_reason = str(error)
            self.path = Path(tempfile.gettempdir()) / f"pwnbao-ai-knowledge-{os.getpid()}-{uuid.uuid4().hex}.sqlite3"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def _session(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self._session() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    feedback_id TEXT PRIMARY KEY,
                    source_hash TEXT NOT NULL,
                    source_fragment TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    proposal_json TEXT NOT NULL,
                    final_json TEXT NOT NULL,
                    proposal_signature TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_feedback_signature ON feedback(proposal_signature, decision);
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    semantic TEXT NOT NULL,
                    matcher_json TEXT NOT NULL,
                    output_json TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    accept_count INTEGER NOT NULL,
                    reject_count INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS response_cache (
                    cache_key TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS corpus_cases (
                    case_id TEXT PRIMARY KEY,
                    source_uri TEXT NOT NULL,
                    source_hash TEXT NOT NULL,
                    split TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    allocator_json TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_corpus_split ON corpus_cases(split, technique);
                CREATE TABLE IF NOT EXISTS evaluation_runs (
                    run_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES corpus_cases(case_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_eval_case ON evaluation_runs(case_id, started_at DESC);
                CREATE TABLE IF NOT EXISTS snapshot_reviews (
                    review_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    proposal_signature TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    effect_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_snapshot_review_case ON snapshot_reviews(case_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS rule_sources (
                    rule_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    feedback_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    holdout_passed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(rule_id, case_id)
                );
                CREATE INDEX IF NOT EXISTS idx_rule_sources_rule ON rule_sources(rule_id, decision);
                CREATE TABLE IF NOT EXISTS regression_fixtures (
                    fixture_id TEXT PRIMARY KEY,
                    feedback_id TEXT NOT NULL,
                    source_hash TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source_fragment TEXT NOT NULL,
                    expected_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_fixture_category ON regression_fixtures(category, created_at DESC);
                """
            )
            connection.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )

    def add_feedback(self, record: FeedbackRecord, proposal_signature: str) -> FeedbackRecord:
        decision = record.decision if record.decision in {"accepted", "modified", "rejected"} else "rejected"
        feedback_id = record.feedback_id or "fb_" + uuid.uuid4().hex
        created_at = record.created_at or _utc_now()
        stored = replace(record, feedback_id=feedback_id, decision=decision, created_at=created_at)
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO feedback(
                    feedback_id, source_hash, source_fragment, decision,
                    proposal_json, final_json, proposal_signature, model,
                    prompt_version, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    stored.feedback_id,
                    stored.source_hash,
                    stored.source_fragment[:12000],
                    stored.decision,
                    json.dumps(stored.proposal, ensure_ascii=False, sort_keys=True),
                    json.dumps(stored.final_value, ensure_ascii=False, sort_keys=True),
                    proposal_signature,
                    stored.model,
                    stored.prompt_version,
                    stored.created_at,
                ),
            )
        return stored

    def upsert_corpus_case(self, payload: dict[str, object]) -> dict[str, object]:
        case_id = str(payload.get("case_id") or "").strip()
        source_hash = str(payload.get("source_hash") or "").strip().lower()
        split = str(payload.get("split") or "").strip()
        technique = str(payload.get("technique") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", case_id):
            raise ValueError("corpus case_id 无效")
        if not re.fullmatch(r"[0-9a-f]{64}", source_hash):
            raise ValueError("corpus source_hash 必须是 SHA256")
        if split not in {"train", "dev", "holdout"}:
            raise ValueError("corpus split 必须是 train/dev/holdout")
        if not technique or len(technique) > 128:
            raise ValueError("corpus technique 无效")
        source_uri = str(payload.get("source_uri") or "")[:2048]
        allocator = dict(payload.get("allocator") or {})
        normalized = {
            **dict(payload),
            "case_id": case_id,
            "source_uri": source_uri,
            "source_hash": source_hash,
            "split": split,
            "technique": technique,
            "allocator": allocator,
        }
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO corpus_cases(
                    case_id, source_uri, source_hash, split, technique,
                    allocator_json, manifest_json, updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    case_id,
                    source_uri,
                    source_hash,
                    split,
                    technique,
                    json.dumps(allocator, ensure_ascii=False, sort_keys=True),
                    json.dumps(normalized, ensure_ascii=False, sort_keys=True),
                    _utc_now(),
                ),
            )
        return normalized

    def list_corpus_cases(self, split: str = "") -> tuple[dict[str, object], ...]:
        query = "SELECT manifest_json FROM corpus_cases"
        params: tuple[object, ...] = ()
        if split:
            query += " WHERE split=?"
            params = (split,)
        query += " ORDER BY technique, case_id"
        with self._lock, self._session() as connection:
            rows = connection.execute(query, params).fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            try:
                value = json.loads(row["manifest_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                result.append(value)
        return tuple(result)

    def save_evaluation_run(self, payload: dict[str, object]) -> dict[str, object]:
        run_id = str(payload.get("run_id") or "run_" + uuid.uuid4().hex)
        case_id = str(payload.get("case_id") or "")
        status = str(payload.get("status") or "pending")
        terminal_statuses = {
            "completed",
            "failed",
            "skipped",
            "offline",
            "over_budget",
            "model",
            "response",
        }
        if status not in {"pending", "running", *terminal_statuses}:
            raise ValueError("evaluation status 无效")
        now = _utc_now()
        started_at = str(payload.get("started_at") or now)
        finished_at = str(payload.get("finished_at") or (now if status in terminal_statuses else ""))
        normalized = {
            **dict(payload),
            "run_id": run_id,
            "case_id": case_id,
            "status": status,
            "started_at": started_at,
            "finished_at": finished_at,
        }
        with self._lock, self._session() as connection:
            if connection.execute("SELECT 1 FROM corpus_cases WHERE case_id=?", (case_id,)).fetchone() is None:
                raise ValueError(f"evaluation case `{case_id}` 未登记")
            connection.execute(
                """
                INSERT OR REPLACE INTO evaluation_runs(
                    run_id, case_id, status, model, prompt_version,
                    metrics_json, result_json, started_at, finished_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id,
                    case_id,
                    status,
                    str(payload.get("model") or ""),
                    str(payload.get("prompt_version") or ""),
                    json.dumps(dict(payload.get("metrics") or {}), ensure_ascii=False, sort_keys=True),
                    json.dumps(dict(payload.get("result") or {}), ensure_ascii=False, sort_keys=True),
                    started_at,
                    finished_at,
                ),
            )
        return normalized

    def add_snapshot_review(self, payload: dict[str, object]) -> dict[str, object]:
        decision = str(payload.get("decision") or "rejected")
        if decision not in {"accepted", "modified", "rejected"}:
            raise ValueError("snapshot review decision 无效")
        normalized = {
            **dict(payload),
            "review_id": str(payload.get("review_id") or "sr_" + uuid.uuid4().hex),
            "decision": decision,
            "created_at": str(payload.get("created_at") or _utc_now()),
        }
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO snapshot_reviews(
                    review_id, case_id, run_id, proposal_signature, decision,
                    effect_json, evidence_json, created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    normalized["review_id"],
                    str(payload.get("case_id") or ""),
                    str(payload.get("run_id") or ""),
                    str(payload.get("proposal_signature") or ""),
                    decision,
                    json.dumps(dict(payload.get("effect") or {}), ensure_ascii=False, sort_keys=True),
                    json.dumps(list(payload.get("evidence") or []), ensure_ascii=False),
                    normalized["created_at"],
                ),
            )
        return normalized

    def add_regression_fixture(
        self,
        *,
        feedback_id: str,
        source_hash: str,
        category: str,
        source_fragment: str,
        expected: dict[str, object],
    ) -> dict[str, object]:
        category = str(category or "semantic")[:64]
        identity = json.dumps(
            {"source_hash": source_hash, "category": category, "source_fragment": source_fragment, "expected": expected},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        fixture_id = "fx_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        payload = {
            "fixture_id": fixture_id,
            "feedback_id": feedback_id,
            "source_hash": source_hash,
            "category": category,
            "source_fragment": source_fragment[:12000],
            "expected": dict(expected),
            "created_at": _utc_now(),
        }
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO regression_fixtures(
                    fixture_id, feedback_id, source_hash, category,
                    source_fragment, expected_json, created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    fixture_id,
                    feedback_id,
                    source_hash,
                    category,
                    payload["source_fragment"],
                    json.dumps(expected, ensure_ascii=False, sort_keys=True),
                    payload["created_at"],
                ),
            )
        return payload

    def list_regression_fixtures(self) -> tuple[dict[str, object], ...]:
        with self._lock, self._session() as connection:
            rows = connection.execute("SELECT * FROM regression_fixtures ORDER BY created_at").fetchall()
        result: list[dict[str, object]] = []
        for row in rows:
            try:
                expected = json.loads(row["expected_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            result.append({
                "fixture_id": row["fixture_id"],
                "feedback_id": row["feedback_id"],
                "source_hash": row["source_hash"],
                "category": row["category"],
                "source_fragment": row["source_fragment"],
                "expected": expected,
                "created_at": row["created_at"],
            })
        return tuple(result)

    def retrieve_examples(self, source: str, limit: int = 6) -> tuple[dict[str, object], ...]:
        source_tokens = _tokens(source)
        with self._lock, self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM feedback ORDER BY created_at DESC LIMIT 300"
            ).fetchall()
        scored = []
        for row in rows:
            fragment = str(row["source_fragment"])
            tokens = _tokens(fragment)
            overlap = len(source_tokens & tokens)
            union = len(source_tokens | tokens) or 1
            score = overlap / union
            if score <= 0 and source_tokens:
                continue
            scored.append((score, str(row["created_at"]), row))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        examples = []
        for score, _created, row in scored[: max(0, int(limit))]:
            try:
                proposal = json.loads(row["proposal_json"])
                final_value = json.loads(row["final_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            examples.append(
                {
                    "feedback_id": row["feedback_id"],
                    "source_fragment": row["source_fragment"],
                    "decision": row["decision"],
                    "proposal": proposal,
                    "final_value": final_value,
                    "similarity": round(score, 4),
                }
            )
        return tuple(examples)

    def is_rejected(self, proposal_signature: str) -> bool:
        with self._lock, self._session() as connection:
            row = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN decision='rejected' THEN 1 ELSE 0 END) AS rejects,
                    SUM(CASE WHEN decision IN ('accepted','modified') THEN 1 ELSE 0 END) AS accepts
                FROM feedback WHERE proposal_signature=?
                """,
                (proposal_signature,),
            ).fetchone()
        return bool(row and int(row["rejects"] or 0) > int(row["accepts"] or 0))

    def save_rule(self, rule: LearnedRule) -> LearnedRule:
        rule_id = rule.rule_id or "rule_" + uuid.uuid4().hex
        now = _utc_now()
        current = next((item for item in self.list_rules(include_disabled=True) if item.rule_id == rule_id), None)
        stored = replace(
            rule,
            rule_id=rule_id,
            created_at=rule.created_at or (current.created_at if current else now),
            updated_at=now,
            accept_count=(current.accept_count + 1) if current else max(1, rule.accept_count),
            reject_count=max(current.reject_count if current else 0, rule.reject_count),
        )
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO rules(
                    rule_id, semantic, matcher_json, output_json, enabled,
                    accept_count, reject_count, source, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    stored.rule_id,
                    stored.semantic,
                    json.dumps(stored.matcher, ensure_ascii=False, sort_keys=True),
                    json.dumps(stored.output, ensure_ascii=False, sort_keys=True),
                    1 if stored.enabled else 0,
                    stored.accept_count,
                    stored.reject_count,
                    stored.source,
                    stored.created_at,
                    stored.updated_at,
                ),
            )
        return stored

    def review_rule_candidate(
        self,
        rule: LearnedRule,
        *,
        case_id: str,
        feedback_id: str = "",
        decision: str = "accepted",
        holdout_passed: bool = False,
        minimum_positive_cases: int = 2,
        require_holdout: bool = True,
        maximum_rejected_cases: int = 0,
    ) -> tuple[LearnedRule, dict[str, object]]:
        """Record independent evidence and enable only well-supported rules."""

        if decision not in {"accepted", "modified", "rejected"}:
            raise ValueError("rule decision 无效")
        case_id = str(case_id or "").strip()
        if not case_id or len(case_id) > 128:
            raise ValueError("rule case_id 无效")
        required_cases = max(1, int(minimum_positive_cases or 1))
        allowed_rejects = max(0, int(maximum_rejected_cases or 0))
        candidate = self.save_rule(replace(rule, enabled=False))
        with self._lock, self._session() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO rule_sources(
                    rule_id, case_id, feedback_id, decision, holdout_passed, created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    candidate.rule_id,
                    case_id,
                    str(feedback_id or ""),
                    decision,
                    1 if holdout_passed else 0,
                    _utc_now(),
                ),
            )
            rows = connection.execute(
                "SELECT decision, holdout_passed FROM rule_sources WHERE rule_id=?",
                (candidate.rule_id,),
            ).fetchall()
            positives = sum(1 for row in rows if row["decision"] in {"accepted", "modified"})
            rejects = sum(1 for row in rows if row["decision"] == "rejected")
            verified = any(bool(row["holdout_passed"]) for row in rows)
            eligible = positives >= required_cases and rejects <= allowed_rejects and (verified or not require_holdout)
            connection.execute(
                """
                UPDATE rules SET enabled=?, accept_count=?, reject_count=?, updated_at=?
                WHERE rule_id=?
                """,
                (1 if eligible else 0, positives, rejects, _utc_now(), candidate.rule_id),
            )
        blocked_by: list[str] = []
        if positives < required_cases:
            blocked_by.append("positive_cases")
        if rejects > allowed_rejects:
            blocked_by.append("rejected_cases")
        if require_holdout and not verified:
            blocked_by.append("holdout")
        status = {
            "eligible": eligible,
            "positive_cases": positives,
            "rejected_cases": rejects,
            "holdout_passed": verified,
            "required_positive_cases": required_cases,
            "require_holdout": require_holdout,
            "maximum_rejected_cases": allowed_rejects,
            "blocked_by": blocked_by,
        }
        return replace(candidate, enabled=eligible, accept_count=positives, reject_count=rejects), status

    def rule_evidence(self, rule_id: str) -> tuple[dict[str, object], ...]:
        with self._lock, self._session() as connection:
            rows = connection.execute(
                "SELECT * FROM rule_sources WHERE rule_id=? ORDER BY created_at",
                (rule_id,),
            ).fetchall()
        return tuple(dict(row) for row in rows)

    def list_rules(self, include_disabled: bool = False) -> tuple[LearnedRule, ...]:
        query = "SELECT * FROM rules" + ("" if include_disabled else " WHERE enabled=1") + " ORDER BY updated_at DESC"
        with self._lock, self._session() as connection:
            rows = connection.execute(query).fetchall()
        result: list[LearnedRule] = []
        for row in rows:
            try:
                matcher = json.loads(row["matcher_json"])
                output = json.loads(row["output_json"])
                if not isinstance(matcher, dict) or not isinstance(output, dict):
                    continue
                result.append(
                    LearnedRule(
                        rule_id=str(row["rule_id"]),
                        semantic=str(row["semantic"]),
                        matcher=matcher,
                        output=output,
                        enabled=bool(row["enabled"]),
                        accept_count=int(row["accept_count"]),
                        reject_count=int(row["reject_count"]),
                        source=str(row["source"]),
                        created_at=str(row["created_at"]),
                        updated_at=str(row["updated_at"]),
                    )
                )
            except (TypeError, ValueError, json.JSONDecodeError, KeyError):
                continue
        return tuple(result)

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> None:
        with self._lock, self._session() as connection:
            connection.execute(
                "UPDATE rules SET enabled=?, updated_at=? WHERE rule_id=?",
                (1 if enabled else 0, _utc_now(), rule_id),
            )

    def delete_rule(self, rule_id: str) -> None:
        with self._lock, self._session() as connection:
            connection.execute("DELETE FROM rules WHERE rule_id=?", (rule_id,))

    def get_cached_result(self, cache_key: str) -> AIAnalysisResult | None:
        with self._lock, self._session() as connection:
            row = connection.execute("SELECT result_json FROM response_cache WHERE cache_key=?", (cache_key,)).fetchone()
        if not row:
            return None
        try:
            return AIAnalysisResult.from_dict(json.loads(row["result_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def put_cached_result(self, cache_key: str, result: AIAnalysisResult) -> None:
        with self._lock, self._session() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO response_cache(cache_key, result_json, created_at) VALUES(?,?,?)",
                (cache_key, json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True), _utc_now()),
            )
            # Bound persistent cache growth without retaining raw EXP text.
            connection.execute(
                "DELETE FROM response_cache WHERE cache_key NOT IN (SELECT cache_key FROM response_cache ORDER BY created_at DESC LIMIT 256)"
            )

    def export_jsonl(self, path: str | os.PathLike[str]) -> int:
        with self._lock, self._session() as connection:
            rows = connection.execute("SELECT * FROM feedback ORDER BY created_at").fetchall()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as stream:
            for row in rows:
                stream.write(
                    json.dumps(
                        {
                            "id": row["feedback_id"],
                            "input": row["source_fragment"],
                            "decision": row["decision"],
                            "proposal": json.loads(row["proposal_json"]),
                            "expected": json.loads(row["final_json"]),
                            "model": row["model"],
                            "prompt_version": row["prompt_version"],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    + "\n"
                )
        return len(rows)


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z_]\w*|0x[0-9a-fA-F]+|\d+", text or "")}
