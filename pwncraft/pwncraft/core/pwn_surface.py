"""Cross-domain Pwn surface assessment.

This module deliberately prevents the Workbench from treating heap analysis as
"the" Pwn model.  It projects already-proven Workspace facts into independent
Pwn domains (stack, heap, format string, control flow, leaks, sandbox, generic
write primitives, integer issues and FILE/FSOP).  It is evidence-led: absence of
facts is ``unknown`` and no vulnerability is inferred merely from imports,
security flags or the existence of a PLT/GOT.

The result is intended for navigation, training-curriculum coverage and audit
summaries.  Domain-specific engines remain authoritative for their own truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Iterable, Mapping

from .capability import analyze_capabilities

if TYPE_CHECKING:
    from .workspace import PwnWorkspace


class PwnDomain(str, Enum):
    STACK = "stack"
    HEAP = "heap"
    FORMAT_STRING = "format_string"
    CONTROL_FLOW = "control_flow"
    LEAK = "leak"
    SYSCALL_SANDBOX = "syscall_sandbox"
    MEMORY_WRITE = "memory_write"
    INTEGER = "integer"
    IO_FILE = "io_file"


@dataclass(frozen=True)
class DomainAssessment:
    domain: PwnDomain
    state: str  # evidenced | partial | unknown
    evidence: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    primitives: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain.value,
            "state": self.state,
            "evidence": list(self.evidence),
            "missing": list(self.missing),
            "primitives": list(self.primitives),
        }


DOMAIN_CATALOG: dict[PwnDomain, dict[str, object]] = {
    PwnDomain.STACK: {
        "title": "Stack",
        "examples": ("stack overflow", "canary", "stack pivot", "ret2win/ROP"),
        "workspace": ("stack", "runtime", "exploit"),
    },
    PwnDomain.HEAP: {
        "title": "Heap",
        "examples": ("UAF", "double free", "off-by-one", "tcache/fastbin/bin state"),
        "workspace": ("heap", "runtime", "exploit"),
    },
    PwnDomain.FORMAT_STRING: {
        "title": "Format String",
        "examples": ("argument offset", "arbitrary read", "format write"),
        "workspace": ("exploit", "leaks"),
    },
    PwnDomain.CONTROL_FLOW: {
        "title": "Control Flow / ROP",
        "examples": ("Control RIP", "ret2libc", "SROP", "ORW", "ROP chain"),
        "workspace": ("stack", "gadgets", "symbols", "libraries", "exploit"),
    },
    PwnDomain.LEAK: {
        "title": "Leaks / Address Derivation",
        "examples": ("libc leak", "PIE leak", "stack leak", "heap leak"),
        "workspace": ("leaks", "libraries", "variables"),
    },
    PwnDomain.SYSCALL_SANDBOX: {
        "title": "Syscall / Sandbox",
        "examples": ("seccomp", "syscall availability", "ORW constraints"),
        "workspace": ("syscalls", "gadgets"),
    },
    PwnDomain.MEMORY_WRITE: {
        "title": "Generic Memory Write",
        "examples": ("arbitrary write", "write-what-where", "OOB write"),
        "workspace": ("exploit", "runtime"),
    },
    PwnDomain.INTEGER: {
        "title": "Integer / Bounds",
        "examples": ("integer overflow", "signedness", "truncation", "OOB"),
        "workspace": ("exploit", "runtime"),
    },
    PwnDomain.IO_FILE: {
        "title": "IO / FILE",
        "examples": ("FILE corruption", "FSOP", "stdio state"),
        "workspace": ("exploit", "runtime", "libraries"),
    },
}


def _primitive_records(workspace: "PwnWorkspace") -> tuple[Mapping[str, object], ...]:
    exploit = workspace.exploit if isinstance(workspace.exploit, dict) else {}
    raw = exploit.get("primitives", [])
    if not isinstance(raw, Iterable) or isinstance(raw, (str, bytes, Mapping)):
        return ()
    return tuple(item for item in raw if isinstance(item, Mapping))


def _primitive_names(workspace: "PwnWorkspace") -> tuple[str, ...]:
    exploit = workspace.exploit if isinstance(workspace.exploit, dict) else {}
    raw = exploit.get("primitives", [])
    names: list[str] = []
    if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, Mapping)):
        for item in raw:
            if isinstance(item, Mapping):
                name = str(item.get("name") or "").strip()
            else:
                name = str(item or "").strip()
            if name:
                names.append(name)
    return tuple(dict.fromkeys(names))


def _matching(primitives: tuple[str, ...], *needles: str) -> tuple[str, ...]:
    lowered = tuple((name, name.lower().replace("-", " ").replace("_", " ")) for name in primitives)
    hits = []
    for original, normalized in lowered:
        if any(needle in normalized for needle in needles):
            hits.append(original)
    return tuple(dict.fromkeys(hits))


def analyze_pwn_surface(workspace: "PwnWorkspace") -> tuple[DomainAssessment, ...]:
    """Project proven Workspace facts into independent Pwn domains.

    This is intentionally a *surface assessment*, not a vulnerability detector.
    ``evidenced`` means the workspace contains domain-specific proof/facts;
    ``partial`` means the domain has some structured state but no decisive
    primitive; ``unknown`` means the tool should not claim anything yet.
    """
    primitives = _primitive_names(workspace)
    capabilities = {item.name: item for item in analyze_capabilities(workspace)}

    stack = workspace.stack if isinstance(workspace.stack, dict) else {}
    heap = workspace.heap if isinstance(workspace.heap, dict) else {}
    syscalls = workspace.syscalls if isinstance(workspace.syscalls, dict) else {}
    policy = syscalls.get("seccomp_policy") if isinstance(syscalls.get("seccomp_policy"), dict) else {}

    results: list[DomainAssessment] = []

    stack_hits = _matching(primitives, "stack overflow", "stack pivot", "control rip", "canary")
    overflow = stack.get("overflow_offset")
    if overflow is not None:
        results.append(DomainAssessment(
            PwnDomain.STACK,
            "evidenced",
            (f"overflow_offset={overflow}",),
            primitives=stack_hits,
        ))
    elif stack_hits:
        results.append(DomainAssessment(PwnDomain.STACK, "evidenced", primitives=stack_hits))
    elif stack:
        results.append(DomainAssessment(
            PwnDomain.STACK,
            "partial",
            ("structured stack workspace facts present",),
            ("no proven overflow/control primitive",),
        ))
    else:
        results.append(DomainAssessment(PwnDomain.STACK, "unknown", missing=("no stack evidence",)))

    heap_hits = _matching(
        primitives,
        "heap", "use after free", "uaf", "double free", "off by one",
        "tcache", "fastbin", "smallbin", "unsorted",
    )
    heap_truth_keys = {"snapshot_id", "step", "chunks", "physical_chunks", "bins", "allocator"}
    if heap_hits:
        results.append(DomainAssessment(PwnDomain.HEAP, "evidenced", primitives=heap_hits))
    elif any(key in heap for key in heap_truth_keys):
        results.append(DomainAssessment(
            PwnDomain.HEAP,
            "partial",
            ("heap model/runtime facts present",),
            ("no explicit heap vulnerability primitive recorded",),
        ))
    else:
        results.append(DomainAssessment(PwnDomain.HEAP, "unknown", missing=("no heap evidence",)))

    fmt_hits = _matching(primitives, "format string", "fmtstr", "format write", "format read")
    if fmt_hits:
        results.append(DomainAssessment(PwnDomain.FORMAT_STRING, "evidenced", primitives=fmt_hits))
    else:
        results.append(DomainAssessment(
            PwnDomain.FORMAT_STRING,
            "unknown",
            missing=("no explicit format-string primitive/offset evidence",),
        ))

    rip_cap = capabilities.get("Control RIP")
    control_hits = _matching(primitives, "control rip", "rop", "ret2", "srop", "stack pivot")
    if rip_cap is not None and rip_cap.state == "available":
        results.append(DomainAssessment(
            PwnDomain.CONTROL_FLOW,
            "evidenced",
            tuple(rip_cap.reasons),
            primitives=control_hits,
        ))
    elif control_hits:
        results.append(DomainAssessment(PwnDomain.CONTROL_FLOW, "evidenced", primitives=control_hits))
    elif any(cap.state == "available" for name, cap in capabilities.items() if name != "Control RIP"):
        ready = tuple(name for name, cap in capabilities.items() if cap.state == "available")
        results.append(DomainAssessment(
            PwnDomain.CONTROL_FLOW,
            "partial",
            tuple(f"capability:{name}" for name in ready),
            ("control-flow hijack itself is not proven",),
        ))
    else:
        results.append(DomainAssessment(PwnDomain.CONTROL_FLOW, "unknown", missing=("no proven control-flow primitive",)))

    if workspace.leaks:
        symbols = tuple(str(item.get("symbol") or "leak") for item in workspace.leaks if isinstance(item, Mapping))
        results.append(DomainAssessment(
            PwnDomain.LEAK,
            "evidenced",
            tuple(f"leak:{name}" for name in symbols) or ("leak records present",),
        ))
    else:
        results.append(DomainAssessment(PwnDomain.LEAK, "unknown", missing=("no leak records",)))

    if policy:
        results.append(DomainAssessment(
            PwnDomain.SYSCALL_SANDBOX,
            "evidenced",
            (f"seccomp entries={len(policy)}",),
        ))
    else:
        results.append(DomainAssessment(PwnDomain.SYSCALL_SANDBOX, "unknown", missing=("no seccomp/syscall policy",)))

    write_hits = _matching(
        primitives,
        "arbitrary write", "write what where", "oob write", "out of bounds write",
        "format string write", "format write",
    )
    if write_hits:
        results.append(DomainAssessment(PwnDomain.MEMORY_WRITE, "evidenced", primitives=write_hits))
    else:
        results.append(DomainAssessment(PwnDomain.MEMORY_WRITE, "unknown", missing=("no generic write primitive recorded",)))

    integer_hits = _matching(primitives, "integer overflow", "signedness", "truncation", "oob", "out of bounds")
    if integer_hits:
        results.append(DomainAssessment(PwnDomain.INTEGER, "evidenced", primitives=integer_hits))
    else:
        results.append(DomainAssessment(PwnDomain.INTEGER, "unknown", missing=("no integer/bounds primitive recorded",)))

    io_hits = _matching(primitives, "fsop", "file corruption", "io file", "_io_")
    if io_hits:
        records = [
            item for item in _primitive_records(workspace)
            if str(item.get("name") or "") in io_hits
        ]
        strong_states = {"", "confirmed", "observed", "proven", "validated", "available"}
        states = tuple(str(item.get("state", "confirmed") or "confirmed").lower() for item in records)
        if not records or any(state in strong_states for state in states):
            # Historical primitive records may omit state; preserve their
            # previous confirmed semantics for backwards compatibility.
            results.append(DomainAssessment(PwnDomain.IO_FILE, "evidenced", primitives=io_hits))
        else:
            results.append(DomainAssessment(
                PwnDomain.IO_FILE,
                "partial",
                tuple(f"EXP primitive state={state}" for state in states),
                ("target/runtime FILE corruption not independently proven",),
                primitives=io_hits,
            ))
    else:
        results.append(DomainAssessment(PwnDomain.IO_FILE, "unknown", missing=("no FILE/FSOP evidence",)))

    return tuple(results)


def active_domains(workspace: "PwnWorkspace") -> tuple[str, ...]:
    """Return domains with actual or partial evidence; never default to heap."""
    return tuple(item.domain.value for item in analyze_pwn_surface(workspace) if item.state != "unknown")


def surface_summary(workspace: "PwnWorkspace") -> dict[str, object]:
    assessments = analyze_pwn_surface(workspace)
    return {
        "domains": [item.to_dict() for item in assessments],
        "active_domains": [item.domain.value for item in assessments if item.state != "unknown"],
        "evidenced_domains": [item.domain.value for item in assessments if item.state == "evidenced"],
        "catalog": {
            domain.value: {
                "title": data["title"],
                "examples": list(data["examples"]),
                "workspace": list(data["workspace"]),
            }
            for domain, data in DOMAIN_CATALOG.items()
        },
    }
