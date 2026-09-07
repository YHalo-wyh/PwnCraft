"""Cross-domain semantic facts derived from explicit source and reviewed target facts.

EXP source evidence proves source intent only.  Compiler/runtime-specific facts are
opt-in reviewed policies and remain distinct from runtime observations.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from pwncraft.features.audit.embedded_compiler import (
    EmbeddedCompilerPolicy,
    analyze_embedded_compiler_semantics,
)
from pwncraft.features.audit.embedded_execution import analyze_embedded_execution_semantics
from pwncraft.features.audit.embedded_program import extract_embedded_function_program
from pwncraft.features.audit.embedded_runtime import (
    EmbeddedRuntimePolicy,
    analyze_embedded_runtime_semantics,
)
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
    """Infer narrow exploit-intent facts from ExploitIR symbol references."""
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


def _embedded_semantic_facts(
    payloads: list,
    compiler_policy: EmbeddedCompilerPolicy | None,
    runtime_policy: EmbeddedRuntimePolicy | None,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Apply reviewed compiler, deterministic execution and reviewed runtime layers."""
    if compiler_policy is None:
        return [], [], []
    compiler_result: list[dict] = []
    execution_result: list[dict] = []
    runtime_result: list[dict] = []
    for payload in payloads:
        program = extract_embedded_function_program(payload.content)
        if program is None:
            continue
        compiler = analyze_embedded_compiler_semantics(program, compiler_policy)
        compiler["source_payload_sha256"] = payload.sha256
        compiler["source_payload_line"] = payload.line
        compiler["source_payload_scope"] = payload.scope
        compiler_result.append(compiler)

        execution = analyze_embedded_execution_semantics(
            program,
            compiler,
            payload.content,
        )
        execution["source_payload_sha256"] = payload.sha256
        execution["source_payload_line"] = payload.line
        execution["source_payload_scope"] = payload.scope
        execution_result.append(execution)

        if runtime_policy is not None:
            runtime = analyze_embedded_runtime_semantics(
                program,
                execution,
                payload.content,
                runtime_policy,
            )
            runtime["source_payload_sha256"] = payload.sha256
            runtime["source_payload_line"] = payload.line
            runtime["source_payload_scope"] = payload.scope
            runtime_result.append(runtime)
    return compiler_result, execution_result, runtime_result


def analyze_exp_semantics(
    source: str,
    *,
    embedded_compiler_policy: EmbeddedCompilerPolicy | None = None,
    embedded_runtime_policy: EmbeddedRuntimePolicy | None = None,
) -> dict:
    """Return source/reviewed-policy semantic facts without executing the target.

    Runtime semantics are intentionally downstream of reviewed compiler facts:
    supplying a runtime policy without a compiler policy does not bypass the type-
    confusion proof requirement.
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
            "embedded_execution_semantics": [],
            "embedded_runtime_semantics": [],
            "primitives": [],
        }
    payloads, payload_error = extract_outbound_literal_payloads(source)
    if payload_error is not None:
        payloads = []
    compiler_facts, execution_facts, runtime_facts = _embedded_semantic_facts(
        payloads,
        embedded_compiler_policy,
        embedded_runtime_policy,
    )
    primitives = infer_exp_primitives(ir)
    for runtime in runtime_facts:
        primitives.extend(runtime.get("primitives") or [])
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
        "embedded_compiler_semantics": compiler_facts,
        "embedded_execution_semantics": execution_facts,
        "embedded_runtime_semantics": runtime_facts,
        "primitives": primitives,
    }


def apply_exp_semantics_to_workspace(
    workspace: "PwnWorkspace",
    source: str,
    *,
    embedded_compiler_policy: EmbeddedCompilerPolicy | None = None,
    embedded_runtime_policy: EmbeddedRuntimePolicy | None = None,
) -> dict:
    """Publish derived primitives while preserving their non-observed state."""
    result = analyze_exp_semantics(
        source,
        embedded_compiler_policy=embedded_compiler_policy,
        embedded_runtime_policy=embedded_runtime_policy,
    )
    if result["status"] != "ok":
        return result
    for primitive in result["primitives"]:
        evidence_items = primitive.get("evidence") or []
        evidence = "; ".join(
            f"L{item.get('line', 0)} {item.get('expression', item.get('kind', ''))}"
            for item in evidence_items
            if isinstance(item, dict)
        )
        workspace.add_primitive(
            str(primitive["name"]),
            evidence=evidence,
            source=str(primitive.get("source") or "exp-ast"),
            state=str(primitive.get("state") or "derived"),
        )
    return result
