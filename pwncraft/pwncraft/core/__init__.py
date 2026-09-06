"""Core services and shared Pwn Workbench state."""

from .tool_actions import ActionType, ToolAction, ToolActionRegistry, default_tool_actions
from .workspace import AddressKind, PwnWorkspace, TypedAddress, WorkspaceVariable
from .workbench import (
    BinaryFacts,
    BinaryInspector,
    EncodingResult,
    GadgetExplorer,
    PaletteEntry,
    SyscallPlan,
    SyscallPlanner,
    encode_value,
    parse_checksec_output,
    search_palette,
)
from .rop import AlignmentResult, ROPChain, ROPEntry, RegisterState, StackState
from .syscalls import SyscallSpec, lookup_syscall, normalize_architecture, parse_seccomp_policy, syscall_table
from .truth import TruthEngine, TruthEvidence
from .pwn_surface import (
    DOMAIN_CATALOG,
    DomainAssessment,
    PwnDomain,
    active_domains,
    analyze_pwn_surface,
    surface_summary,
)
from .stack_truth import (
    RuntimeRegisterObservation,
    StackOverflowEvidence,
    confirm_saved_ip_control,
    derive_cyclic_overflow,
    derive_saved_ip_control_from_observation,
    publish_stack_evidence,
    stack_control_state,
)

__all__ = [
    "ActionType",
    "AddressKind",
    "PwnWorkspace",
    "ToolAction",
    "ToolActionRegistry",
    "TypedAddress",
    "WorkspaceVariable",
    "default_tool_actions",
    "BinaryFacts",
    "BinaryInspector",
    "EncodingResult",
    "GadgetExplorer",
    "PaletteEntry",
    "SyscallPlan",
    "SyscallPlanner",
    "encode_value",
    "parse_checksec_output",
    "search_palette",
    "AlignmentResult",
    "ROPChain",
    "ROPEntry",
    "RegisterState",
    "StackState",
    "SyscallSpec",
    "lookup_syscall",
    "normalize_architecture",
    "parse_seccomp_policy",
    "syscall_table",
    "TruthEngine",
    "TruthEvidence",
    "DOMAIN_CATALOG",
    "DomainAssessment",
    "PwnDomain",
    "active_domains",
    "analyze_pwn_surface",
    "surface_summary",
    "RuntimeRegisterObservation",
    "StackOverflowEvidence",
    "confirm_saved_ip_control",
    "derive_cyclic_overflow",
    "derive_saved_ip_control_from_observation",
    "publish_stack_evidence",
    "stack_control_state",
]
