from pwncraft.features.heapviz.allocators.profiles import build_allocator_config
from pwncraft.features.heapviz.analyzer import BranchGroup, HeapAnalysisResult, ParseDiagnostic, SourceBinding, TimelineOverride, analyze_heap_source
from pwncraft.features.heapviz.api_profile import infer_api_profile_from_source, render_api_call
from pwncraft.features.heapviz.benchmark import BenchmarkCaseResult, SemanticBenchmarkReport, SemanticBenchmarkRunner, default_benchmark_path
from pwncraft.features.heapviz.codegen import generate_pwntools
from pwncraft.features.heapviz.compatibility import config_capability_summary, target_compatibility, template_compatibility
from pwncraft.features.heapviz.constraints import ConstraintEngine, ConstraintResult, EditRequest, ValidationStatus
from pwncraft.features.heapviz.contracts import HelperContract, HelperContractResolver
from pwncraft.features.heapviz.corrections import CorrectionEngine, CorrectionPatch
from pwncraft.features.heapviz.engine import GlibcHeapEngine
from pwncraft.features.heapviz.events import AllocEvent, BinTransitionEvent, FreeEvent, OverwriteEdge, ReadEvent, WriteEvent, WriteImpact, WriteImpactKind
from pwncraft.features.heapviz.memory import MemoryAddress, MemoryObject, MemoryProvenance, MemorySpan, PhysicalMemory, PhysicalMemorySnapshot, ProvenanceKind
from pwncraft.features.heapviz.models import AllocatorAbort, AllocatorConfig, BinState, ChunkField, ChunkState, HandleState, HeapApiProfile, HeapIntent, HeapSnapshot, HeapWarning, MemoryRegion, ValueObservation
from pwncraft.features.heapviz.operations import HeapOperation, HeapOperationKind, HeapOperationLayer
from pwncraft.features.heapviz.payload import PayloadEvaluator, PayloadIR, PayloadSegment
from pwncraft.features.heapviz.pwndbg import HeapDiff, ObservedHeapState, diff_snapshot, parse_pwndbg_snapshot
from pwncraft.features.heapviz.presentation import CanvasLayoutModel, HeapVisualModelBuilder, PaintSpan, VisualKind
from pwncraft.features.heapviz.scenario import HeapScenario
from pwncraft.features.heapviz.semantics import (
    AbstractValue,
    BehaviorEffect,
    CallTarget,
    CanonicalHeapOperation,
    CanonicalOperationKind,
    ChallengeBehaviorProfile,
    ChallengeCallBehavior,
    ProgramEvidence,
    ProgramEvent,
    SemanticExpression,
    evaluate_value,
    parse_semantic_expression,
)
from pwncraft.features.heapviz.templates import HEAP_TEMPLATES, HeapTemplate
from pwncraft.features.heapviz.validation import validate_scenario
from pwncraft.features.heapviz.views import ArenaLink, BinHeadView, ChunkMemoryView, TopChunkView, TypedFieldValue, TypedMemoryView

__all__ = [
    "AllocatorConfig",
    "AllocatorAbort",
    "AllocEvent",
    "BehaviorEffect",
    "BenchmarkCaseResult",
    "BranchGroup",
    "CanvasLayoutModel",
    "BinState",
    "BinTransitionEvent",
    "CallTarget",
    "ChallengeBehaviorProfile",
    "ChallengeCallBehavior",
    "ChunkState",
    "ChunkField",
    "ChunkMemoryView",
    "CanonicalHeapOperation",
    "CanonicalOperationKind",
    "ConstraintEngine",
    "ConstraintResult",
    "CorrectionEngine",
    "CorrectionPatch",
    "EditRequest",
    "ArenaLink",
    "BinHeadView",
    "GlibcHeapEngine",
    "HeapApiProfile",
    "HeapAnalysisResult",
    "parse_pwndbg_snapshot",
    "diff_snapshot",
    "template_compatibility",
    "target_compatibility",
    "config_capability_summary",
    "ObservedHeapState",
    "HeapDiff",
    "HeapOperationLayer",
    "HeapIntent",
    "HandleState",
    "HeapOperation",
    "HeapOperationKind",
    "HeapScenario",
    "HeapSnapshot",
    "HeapTemplate",
    "HeapWarning",
    "HeapVisualModelBuilder",
    "HelperContract",
    "HelperContractResolver",
    "MemoryRegion",
    "MemoryAddress",
    "MemoryObject",
    "MemoryProvenance",
    "MemorySpan",
    "OverwriteEdge",
    "PayloadEvaluator",
    "PayloadIR",
    "PayloadSegment",
    "PaintSpan",
    "PhysicalMemory",
    "PhysicalMemorySnapshot",
    "ProvenanceKind",
    "ReadEvent",
    "FreeEvent",
    "WriteEvent",
    "WriteImpact",
    "WriteImpactKind",
    "TopChunkView",
    "TypedFieldValue",
    "TypedMemoryView",
    "ParseDiagnostic",
    "ProgramEvidence",
    "ProgramEvent",
    "SemanticExpression",
    "AbstractValue",
    "SemanticBenchmarkReport",
    "SemanticBenchmarkRunner",
    "SourceBinding",
    "TimelineOverride",
    "ValueObservation",
    "ValidationStatus",
    "VisualKind",
    "HEAP_TEMPLATES",
    "build_allocator_config",
    "default_benchmark_path",
    "analyze_heap_source",
    "generate_pwntools",
    "evaluate_value",
    "infer_api_profile_from_source",
    "render_api_call",
    "parse_semantic_expression",
    "validate_scenario",
]
