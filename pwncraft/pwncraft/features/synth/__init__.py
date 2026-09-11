"""Rule-driven exploit synthesis (VNext.3.1#9 Primitive Graph → VNext.4 Strategy).

Deterministic-first: every node/strategy carries the evidence it was derived
from; anything not provable from ELF bytes, disassembly or existing workspace
truth is reported as blocked/unknown instead of guessed.  No LLM, no network.
"""
from .facts import TargetFacts, collect_target_facts
from .graph import PrimitiveGraph, build_primitive_graph
from .pipeline import analyze_target, generate_exp, deposit_case
from .strategy import ExploitStrategy, plan_strategies

__all__ = [
    "TargetFacts",
    "collect_target_facts",
    "PrimitiveGraph",
    "build_primitive_graph",
    "ExploitStrategy",
    "plan_strategies",
    "analyze_target",
    "generate_exp",
    "deposit_case",
]
