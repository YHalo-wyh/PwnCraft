from __future__ import annotations

from dataclasses import dataclass

from pwncraft.features.heapviz.semantics.symbolic import SemanticExpression


@dataclass(frozen=True)
class CallTarget:
    qualified_name: str
    function_name: str
    receiver: str = ""
    receiver_type: str = "unknown"
    origin: str = "heuristic"  # profile | user_helper | learned | challenge_receiver | python_builtin | heuristic

    @property
    def is_method(self) -> bool:
        return bool(self.receiver)


@dataclass(frozen=True)
class ProgramEvidence:
    kind: str
    detail: str
    line: int = 0
    confidence: float = 0.0


@dataclass(frozen=True)
class ProgramEvent:
    event_id: str
    kind: str  # call | read | write | value | selector
    target: CallTarget
    args: tuple[SemanticExpression, ...] = ()
    keywords: tuple[tuple[str, SemanticExpression], ...] = ()
    source: str = ""
    line: int = 0
    start: int = 0
    end: int = 0
    result: str = ""
    confidence: float = 0.0
    evidence: tuple[ProgramEvidence, ...] = ()

    def argument_sources(self) -> tuple[tuple[str, ...], dict[str, str]]:
        return tuple(item.source for item in self.args), {name: item.source for name, item in self.keywords}

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "kind": self.kind,
            "target": {
                "qualified_name": self.target.qualified_name,
                "function_name": self.target.function_name,
                "receiver": self.target.receiver,
                "receiver_type": self.target.receiver_type,
                "origin": self.target.origin,
            },
            "args": [item.to_dict() for item in self.args],
            "keywords": {name: item.to_dict() for name, item in self.keywords},
            "source": self.source,
            "line": self.line,
            "start": self.start,
            "end": self.end,
            "result": self.result,
            "confidence": self.confidence,
            "evidence": [item.__dict__ for item in self.evidence],
        }
