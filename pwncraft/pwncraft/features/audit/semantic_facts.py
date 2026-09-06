"""Cross-domain semantic facts derived only from ExploitIR source evidence.

This module intentionally models *EXP intent*, not target vulnerability truth.
A referenced libc symbol proves that the exploit source names that object; it
does not prove the target contains a reachable corruption primitive or that the
exploit succeeds at runtime.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pwncraft.features.audit.embedded_compiler import (
    EmbeddedCompilerPolicy,
    analyze_embedded_compiler_semantics,
)
from pwncraft.features.audit.embedded_program import extract_embedded_function_program
from pwncraft.features.audit.extract import extract_exploit_ir
from pwncraft.features.audit.model import ExploitIR, SymbolRef
from pwncraft.features.audit.outbound_payload import extract_outbound_literal_payloads

if TYPE_CHECKING:
    from pwncraft.core.workspace import PwnWorkspace


def _ref_evidence(ref: SymbolRef) -> dict:
    return {
        "kind": "EXP_SYMBOL_REF",
        "expression": ref.expression,
        "namespace": ref.namespace,
        "symbol": ref.symbol,
        "line": ref.line,
        "scope": ref.scope,
        "provenance": "EXP_AST",
    }


def infer_exp_primitives(ir: ExploitIR) -> list[dict]:
    """Infer narrow, reviewable exploit-intent primitives from an ExploitIR.

    Current FSOP rule requires both:
      1. a standard libc FILE object reference (``_IO_2_1_*``), and
      2. an ``_IO_*_jumps`` vtable reference.

    This conjunction is intentionally stronger than seeing ``system`` or one
    FILE symbol in isolation, but the resulting state remains ``derived``.
    """
    refs = list(ir.symbol_refs)
    stream_refs = [ref for ref in refs if ref.symbol.startswith("_IO_2_1_")]
    vtable_refs = [
        ref for ref in refs
        if ref.symbol.startswith("_IO_") and ref.symbol.endswith("_jumps")
    ]

    primitives: list[dict] = []
    if stream_refs and vtable_refs:
        selected: list[SymbolRef] = []
        seen: set[tuple[str, int]] = set()
        for ref in stream_refs + vtable_refs:
            key = (ref.expression, ref.line)
            if key not in seen:
                seen.add(key)
                selected.append(ref)
        target_refs = [ref for ref in refs if ref.symbol in {"system", "execve"}]
        evidence = [_ref_evidence(ref) for ref in selected]
        evidence.extend(_ref_evidence(ref) for ref in target_refs)
        primitives.append({
            "name": "FSOP / FILE corruption intent",
            "domain": "io_file",
            "state": "derived",
            "source": "exp-ast",
            "confidence": 0.9,
            "evidence": evidence,
            "limitations": [
                "EXP symbol references do not prove a target-side FILE corruption primitive",
                "runtime reachability and exploit success are not observed",
            ],
        })
    return primitives


def _embedded_program_facts(payloads: list) -> list[dict]:
    """Parse second-language structure only from already-proven outbound literals."""
    result: list[dict] = []
    for payload in payloads:
        program = extract_embedded_function_program(payload.content)
        if program is None:
            continue
        fact = program.to_dict()
        fact["source_payload_sha256"] = payload.sha256
        fact["source_payload_line"] = payload.line
        fact["source_payload_scope"] = payload.scope
        result.append(fact)
    return result


def _embedded_compiler_facts(
    payloads: list,
    policy: EmbeddedCompilerPolicy | None,
) -> list[dict]:
    """Apply compiler semantics only when an explicit reviewed policy exists."""
    if policy is None:
        return []
    result: list[dict] = []
    for payload in payloads:
        program = extract_embedded_function_program(payload.content)
        if program is None:
            continue
        fact = analyze_embedded_compiler_semantics(program, policy)
        fact["source_payload_sha256"] = payload.sha256
        fact["source_payload_line"] = payload.line
        fact["source_payload_scope"] = payload.scope
        result.append(fact)
    return result


def analyze_exp_semantics(
    source: str,
    *,
    embedded_compiler_policy: EmbeddedCompilerPolicy | None = None,
) -> dict:
    """Return source-derived semantic facts without mutating a workspace.

    Compiler-specific facts are opt-in and require a reviewed policy.  The
    default path therefore preserves Cycle-15 behavior and cannot infer slot
    allocation from source shape alone.
    """
    ir, syntax_error = extract_exploit_ir(source)
    if syntax_error is not None:
        return {
            "status": "blocked",
            "reason": "EXP_PARSE",
            "line": syntax_error.lineno or 0,
            "message": syntax_error.msg,
            "symbol_refs": [],
            "outbound_literal_payloads": [],
            "embedded_programs": [],
            "embedded_compiler_semantics": [],
            "primitives": [],
        }
    payloads, payload_error = extract_outbound_literal_payloads(source)
    # Both extractors consume the same Python grammar.  Keep this defensive
    # branch explicit rather than silently dropping payload evidence if they ever
    # diverge in supported syntax.
    if payload_error is not None:
        payloads = []
    return {
        "status": "ok",
        "reason": "",
        "symbol_refs": [
            {
                "expression": ref.expression,
                "namespace": ref.namespace,
                "symbol": ref.symbol,
                "line": ref.line,
                "scope": ref.scope,
            }
            for ref in ir.symbol_refs
        ],
        "outbound_literal_payloads": [payload.to_dict() for payload in payloads],
        "embedded_programs": _embedded_program_facts(payloads),
        "embedded_compiler_semantics": _embedded_compiler_facts(
            payloads, embedded_compiler_policy
        ),
        "primitives": infer_exp_primitives(ir),
    }


def apply_exp_semantics_to_workspace(
    workspace: "PwnWorkspace",
    source: str,
    *,
    embedded_compiler_policy: EmbeddedCompilerPolicy | None = None,
) -> dict:
    """Publish EXP-derived primitives with their non-observed state intact."""
    result = analyze_exp_semantics(
        source, embedded_compiler_policy=embedded_compiler_policy
    )
    if result["status"] != "ok":
        return result
    for primitive in result["primitives"]:
        evidence_items = primitive.get("evidence") or []
        evidence = "; ".join(
            f"L{item.get('line', 0)} {item.get('expression', '')}"
            for item in evidence_items
        )
        workspace.add_primitive(
            str(primitive["name"]),
            evidence=evidence,
            source=str(primitive.get("source") or "exp-ast"),
            state=str(primitive.get("state") or "derived"),
        )
    return result
