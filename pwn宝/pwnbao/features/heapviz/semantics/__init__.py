"""Program semantics and challenge-specific behavior expansion for HeapViz."""

from pwnbao.features.heapviz.semantics.challenge_profile import (
    BehaviorEffect,
    ChallengeBehaviorProfile,
    ChallengeCallBehavior,
)
from pwnbao.features.heapviz.semantics.effect_expander import BehaviorEffectExpander
from pwnbao.features.heapviz.semantics.canonical_ir import (
    CanonicalHeapOperation,
    CanonicalOperationKind,
    CanonicalSourceBinding,
    SemanticConfidence,
    canonical_from_legacy,
    canonicalize_operations,
    legacy_from_canonical,
)
from pwnbao.features.heapviz.semantics.program_ir import CallTarget, ProgramEvidence, ProgramEvent
from pwnbao.features.heapviz.semantics.symbolic import SemanticExpression, parse_semantic_expression
from pwnbao.features.heapviz.semantics.values import (
    AbstractValue,
    ConcreteBytes,
    ConcreteInt,
    LengthExpr,
    PointerExpr,
    SymbolicBytes,
    SymbolicInt,
    UnknownValue,
    byte_length,
    evaluate_value,
)

__all__ = [
    "BehaviorEffect",
    "BehaviorEffectExpander",
    "AbstractValue",
    "CallTarget",
    "CanonicalHeapOperation",
    "CanonicalOperationKind",
    "CanonicalSourceBinding",
    "ChallengeBehaviorProfile",
    "ChallengeCallBehavior",
    "ConcreteBytes",
    "ConcreteInt",
    "LengthExpr",
    "PointerExpr",
    "ProgramEvidence",
    "ProgramEvent",
    "SemanticConfidence",
    "SemanticExpression",
    "SymbolicBytes",
    "SymbolicInt",
    "UnknownValue",
    "byte_length",
    "canonical_from_legacy",
    "canonicalize_operations",
    "evaluate_value",
    "legacy_from_canonical",
    "parse_semantic_expression",
]
