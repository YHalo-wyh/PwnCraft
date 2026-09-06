"""Cross-domain semantic facts derived only from ExploitIR source evidence.

This module intentionally models *EXP intent*, not target vulnerability truth.
A referenced libc symbol proves that the exploit source names that object; it
does not prove the target contains a reachable corruption primitive or that the
exploit succeeds at runtime.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

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


def analyze_exp_semantics(source: str) -> dict:
    """Return source-derived semantic facts without mutating a workspace."""
    ir, syntax_error = extract_exploit_ir(source)
    if syntax_error is not None:
        return {
            "status": "blocked",
            "reason": "EXP_PARSE",
            "line": syntax_error.lineno or 0,
            "message": syntax_error.msg,
            "symbol_refs": [],
            "outbound_literal_payloads": [],
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
        "primitives": infer_exp_primitives(ir),
    }


def apply_exp_semantics_to_workspace(
    workspace: "PwnWorkspace", source: str
) -> dict:
    """Publish EXP-derived primitives with their non-observed state intact."""
    result = analyze_exp_semantics(source)
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
