from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import replace

from .knowledge import AIKnowledgeStore
from .models import AIAnalysisRequest, AIAnalysisResult, AIProviderConfig
from .provider import LocalAIProvider, ProviderError
from .validator import validate_ai_response


class AIAnalysisCoordinator:
    """Thread-safe generation, cache and offline-backoff coordinator."""

    def __init__(self, knowledge: AIKnowledgeStore):
        self.knowledge = knowledge
        self._lock = threading.RLock()
        self._latest_generation = 0
        self._failures = 0
        self._backoff_until = 0.0

    def next_generation(self) -> int:
        with self._lock:
            self._latest_generation += 1
            return self._latest_generation

    def is_latest(self, generation: int) -> bool:
        with self._lock:
            return generation == self._latest_generation

    def cache_key(self, request: AIAnalysisRequest, config: AIProviderConfig) -> str:
        static_raw = json.dumps(request.static_result, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
        canonical = {
            "source_hash": request.source_hash,
            "allocator": request.allocator,
            # Branch selections, timeline overrides and analyzer diagnostics can
            # change while source text stays identical.  Cache those states by
            # digest without persisting another copy of the complete IR here.
            "static_result_hash": hashlib.sha256(static_raw.encode("utf-8")).hexdigest(),
            "current_snapshot": request.current_snapshot,
            "observed_heap": request.observed_heap,
            "observed_diff": request.observed_diff,
            "instruction": request.instruction,
            "rules": request.learned_rules,
            "examples": [item.get("feedback_id") for item in request.examples],
            "prompt_version": request.prompt_version,
            "model": config.model,
            "base_url": config.normalized_base_url(),
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "context_budget_tokens": config.context_budget_tokens,
            "max_input_tokens": config.max_input_tokens,
            "json_prefill": config.json_prefill,
        }
        raw = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def analyze(self, provider: LocalAIProvider, request: AIAnalysisRequest, config: AIProviderConfig) -> AIAnalysisResult:
        cache_key = self.cache_key(request, config)
        try:
            cached = self.knowledge.get_cached_result(cache_key)
        except (OSError, sqlite3.Error):
            cached = None
        if cached is not None:
            validated, cache_diagnostics = validate_ai_response(
                {
                    "source_hash": cached.source_hash,
                    "proposals": [item.to_dict() for item in cached.proposals],
                    "diagnostics": [],
                },
                request.source,
                request.source_hash,
            )
            filtered = tuple(item for item in validated if not self._is_rejected(item.signature()))
            diagnostics = (*cached.diagnostics, *cache_diagnostics)
            if len(filtered) != len(cached.proposals):
                diagnostics = (*diagnostics, "已根据全局负反馈隐藏缓存中的重复候选。")
            return replace(cached, generation=request.generation, proposals=filtered, diagnostics=diagnostics, cached=True)
        with self._lock:
            remaining = self._backoff_until - time.monotonic()
        if remaining > 0:
            raise ProviderError(f"AI 服务暂停重试，请 {remaining:.0f} 秒后再试。")
        try:
            result = provider.analyze(request)
        except ProviderError as error:
            if error.retryable:
                with self._lock:
                    self._failures += 1
                    delay = (5, 15, 60)[min(self._failures - 1, 2)]
                    self._backoff_until = time.monotonic() + delay
            raise
        with self._lock:
            self._failures = 0
            self._backoff_until = 0.0
        filtered = tuple(item for item in result.proposals if not self._is_rejected(item.signature()))
        if len(filtered) != len(result.proposals):
            result = replace(result, proposals=filtered, diagnostics=(*result.diagnostics, "已根据全局负反馈隐藏重复候选。"))
        # Cache offsets/fingerprints and semantic payloads, not duplicated EXP
        # text. On a cache hit the validator reconstructs source_text from the
        # current source after source_hash/range checks.
        cache_result = replace(
            result,
            proposals=tuple(replace(item, source_text="") for item in result.proposals),
        )
        try:
            self.knowledge.put_cached_result(cache_key, cache_result)
        except (OSError, sqlite3.Error):
            result = replace(result, diagnostics=(*result.diagnostics, "知识库缓存不可写，本次结果仅保留在当前界面。"))
        return result

    def _is_rejected(self, signature: str) -> bool:
        try:
            return self.knowledge.is_rejected(signature)
        except (OSError, sqlite3.Error):
            return False

    def reset_backoff(self) -> None:
        with self._lock:
            self._failures = 0
            self._backoff_until = 0.0
