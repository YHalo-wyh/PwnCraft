from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TruthEvidence:
    value: object
    source: str
    evidence: str = ""
    confidence: str = "confirmed"
    observed: bool = False


class TruthProvider(Protocol):
    name: str

    def query(self, key: str, **context: object) -> TruthEvidence | None: ...


class TruthEngine:
    """Provider multiplexer for facts; it never asks an AI to invent values."""

    def __init__(self, providers: list[TruthProvider] | None = None):
        self.providers = list(providers or [])

    def add_provider(self, provider: TruthProvider) -> None:
        self.providers.append(provider)

    def query(self, key: str, **context: object) -> TruthEvidence | None:
        for provider in self.providers:
            result = provider.query(str(key), **context)
            if result is not None:
                return result
        return None

    def require(self, key: str, **context: object) -> TruthEvidence:
        result = self.query(key, **context)
        if result is None:
            raise LookupError(f"没有已确认的事实: {key}")
        return result

    def query_observed(self, key: str, **context: object) -> TruthEvidence | None:
        """Return only provider evidence explicitly marked as observed."""
        for provider in self.providers:
            result = provider.query(str(key), **context)
            if result is not None and result.observed:
                return result
        return None
