from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from pwncraft.features.heapviz import (
    GlibcHeapEngine,
    HeapOperationKind,
    analyze_heap_source,
    build_allocator_config,
    infer_api_profile_from_source,
)

_EXP_NAME = re.compile(r"^(?:exp|exploit|solve|pwn)(?:[_\-.]|\d|$)", re.IGNORECASE)
_CORE_KINDS = {
    HeapOperationKind.ALLOC,
    HeapOperationKind.FREE,
    HeapOperationKind.EDIT,
    HeapOperationKind.SHOW,
    HeapOperationKind.COPY,
}


def _candidate_paths(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if _EXP_NAME.match(path.name))


def _target_signals(source: str) -> bool:
    return bool(re.search(r"\b(?:from\s+pwn\s+import|remote\s*\(|process\s*\(|ELF\s*\(|send(?:line|all|after)?\s*\(|recv)", source))


def _allocator_hint(path: Path, source: str) -> tuple[str, str]:
    arch = "i386" if re.search(r"(?:arch\s*=\s*['\"]i386|context\.arch\s*=\s*['\"]i386)", source) else "amd64"
    combined = str(path) + "\n" + source[:12000]
    versions = re.findall(r"(?:glibc|libc)[-_ ]?(2\.\d{1,2})", combined, flags=re.IGNORECASE)
    return arch, f"glibc {versions[0]}" if versions else "glibc 2.35"


def _core_count(result) -> int:
    return sum(item.kind in _CORE_KINDS for item in result.operations)


def _best_replay_variant(source: str, profile, result):
    """Find an explicit but unresolved source branch/zero-arg entrypoint.

    The selected variant is labelled PARTIAL_REPLAY; it is not claimed to be
    the runtime path.  This makes argument-driven EXPs inspectable without
    silently choosing a branch as truth.
    """
    best = result
    variant = "default"
    for group in result.branch_groups:
        for choice in group.choices:
            candidate = analyze_heap_source(
                source, profile, branch_choices={group.branch_id: choice},
                max_loop_iterations=1024, max_events=4096,
            )
            if _core_count(candidate) > _core_count(best):
                best = candidate
                variant = f"unresolved branch candidate: {group.condition}={choice}"
    if _core_count(best):
        return best, variant
    try:
        module = ast.parse(source)
    except SyntaxError:
        return best, variant
    for node in module.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not re.match(r"^(?:case_|exploit$|pwn$|attack$|solve$)", node.name, re.I):
            continue
        positional = len(node.args.posonlyargs) + len(node.args.args)
        required = positional - len(node.args.defaults)
        if required or node.args.kwonlyargs and any(value is None for value in node.args.kw_defaults):
            continue
        candidate = analyze_heap_source(
            source + f"\n{node.name}()\n", profile,
            max_loop_iterations=1024, max_events=4096,
        )
        if _core_count(candidate) > _core_count(best):
            best = candidate
            variant = f"zero-argument entrypoint candidate: {node.name}()"
    return best, variant


def _final_snapshot(snapshot) -> dict[str, object]:
    return {
        "step": snapshot.step,
        "aborted": snapshot.aborted,
        "chunks": {
            chunk_id: {
                "address": chunk.address,
                "user_address": chunk.user_address,
                "request_size": chunk.request_size,
                "chunk_size": chunk.chunk_size,
                "lifecycle": chunk.lifecycle,
                "bin_location": chunk.bin_location,
                "fd": chunk.fd,
                "bk": chunk.bk,
                "provenance": chunk.provenance,
            }
            for chunk_id, chunk in snapshot.chunks.items()
        },
        "bins": asdict(snapshot.bins),
        "warnings": [asdict(item) for item in snapshot.warnings],
    }


def evaluate_file(path: Path, root: Path, output_dir: Path) -> dict[str, object]:
    data = path.read_bytes()
    source = data.decode("utf-8", errors="replace")
    digest = hashlib.sha256(data).hexdigest()
    relative = path.relative_to(root).as_posix()
    try:
        ast.parse(source)
        syntax_valid = True
        syntax_error = ""
    except SyntaxError as error:
        syntax_valid = False
        syntax_error = f"{error.lineno or 0}:{error.msg}"

    profile, found = infer_api_profile_from_source(source)
    result = analyze_heap_source(source, profile, max_loop_iterations=1024, max_events=4096)
    result, analysis_variant = _best_replay_variant(source, profile, result)
    arch, libc = _allocator_hint(path, source)
    engine = GlibcHeapEngine(build_allocator_config(arch, libc))
    snapshots = engine.replay(result.operations)
    final = snapshots[-1]
    kinds = Counter(item.kind.value for item in result.operations)
    core = [item for item in result.operations if item.kind in _CORE_KINDS]
    has_alloc = any(item.kind == HeapOperationKind.ALLOC for item in core)
    target = _target_signals(source)
    reasons: list[str] = []
    diagnostic_codes = [item.code for item in result.diagnostics]
    if not syntax_valid:
        reasons.append("syntax invalid")
    if any(code in {"unsupported_call", "unresolved_call", "unsupported_helper"} for code in diagnostic_codes):
        reasons.append("unsupported helper semantics")
    unknown_sizes = [
        item for item in result.operations
        if item.kind == HeapOperationKind.ALLOC and engine.request2size(item.request_size) is None
    ]
    if unknown_sizes:
        reasons.append("unknown allocation size")
    if any(code in {"dynamic_index", "unresolved_index", "symbolic_loop"} for code in diagnostic_codes):
        reasons.append("dynamic index unresolved")
    if any(code in {"payload_unknown", "unsupported_payload", "payload_truncated"} for code in diagnostic_codes):
        reasons.append("unsupported payload transform")
    if not re.search(r"glibc\s+2\.\d+", libc):
        reasons.append("unknown libc version")
    if final.aborted:
        reasons.append(
            "unsupported allocator transition: "
            + (final.allocator_abort.reason if final.allocator_abort else "allocator abort")
        )
    if target and not core:
        reasons.append("external runtime dependency")
    if analysis_variant != "default":
        reasons.append(analysis_variant + "; runtime selection unresolved")

    # Levels are deliberately monotonic.  SEMANTIC_VERIFIED requires an
    # external truth oracle and is never inferred from the simulator itself.
    semantic_oracle = path.with_suffix(path.suffix + ".semantic.json")
    if semantic_oracle.is_file():
        status = "SEMANTIC_VERIFIED"
    elif has_alloc and not reasons and all(item.provenance != "unknown" for item in final.chunks.values()):
        status = "FULL_REPLAY"
    elif has_alloc:
        status = "PARTIAL_REPLAY"
    elif core:
        status = "MODEL_READY"
    else:
        status = "PARSE_ONLY"
    if status != "SEMANTIC_VERIFIED" and not reasons:
        reasons.append("external semantic truth oracle not provided")

    if not core:
        eligibility = "RUNTIME_REQUIRED"
        eligibility_reason = "no in-file deterministic heap operation; imported/runtime helper or non-heap candidate"
    elif any("runtime selection unresolved" in reason for reason in reasons) or unknown_sizes:
        eligibility = "STATIC_PARTIAL"
        eligibility_reason = "heap structure is static, but one or more values/branches remain symbolic"
    else:
        eligibility = "STATIC_ELIGIBLE"
        eligibility_reason = "in-file AST supplies a deterministic heap operation model"

    case_payload = {
        "schema_version": 2,
        "path": relative,
        "source_hash": digest,
        "syntax_valid": syntax_valid,
        "syntax_error": syntax_error,
        "model_status": status,
        "static_eligibility": eligibility,
        "eligibility_reason": eligibility_reason,
        "analysis_variant": analysis_variant,
        "failure_reasons": reasons,
        "semantic_verified": status == "SEMANTIC_VERIFIED",
        "allocator": {"arch": arch, "libc": libc, "mode": "strict"},
        "api_profile": found,
        "operations": [item.to_dict() for item in result.operations],
        "diagnostics": [asdict(item) for item in result.diagnostics],
        "branch_groups": [asdict(item) for item in result.branch_groups],
        "final_snapshot": _final_snapshot(final),
    }
    case_dir = output_dir / "cases"
    case_dir.mkdir(parents=True, exist_ok=True)
    artifact_name = f"{digest[:16]}.json"
    (case_dir / artifact_name).write_text(json.dumps(case_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "path": relative,
        "source_hash": digest,
        "artifact": f"cases/{artifact_name}",
        "syntax_valid": syntax_valid,
        "model_status": status,
        "static_eligibility": eligibility,
        "eligibility_reason": eligibility_reason,
        "analysis_variant": analysis_variant,
        "operation_count": len(result.operations),
        "operation_kinds": dict(sorted(kinds.items())),
        "chunk_count": len(final.chunks),
        "aborted": final.aborted,
        "branch_count": len(result.branch_groups),
        "diagnostic_codes": diagnostic_codes,
        "failure_reasons": reasons,
        "semantic_verified": status == "SEMANTIC_VERIFIED",
        "api_profile": found,
    }


def render_markdown(root: Path, rows: list[dict[str, object]]) -> str:
    counts = Counter(str(row["model_status"]) for row in rows)
    eligibility = Counter(str(row["static_eligibility"]) for row in rows)
    ready = {"MODEL_READY", "PARTIAL_REPLAY", "FULL_REPLAY", "SEMANTIC_VERIFIED"}
    raw_pass = sum(str(row["model_status"]) in ready for row in rows)
    static_scope = [row for row in rows if row["static_eligibility"] != "RUNTIME_REQUIRED"]
    static_pass = sum(str(row["model_status"]) in ready for row in static_scope)
    lines = [
        "# Sunshine EXP AST / HeapViz 批量回放报告",
        "",
        f"- corpus: `{root}`",
        f"- EXP candidates: **{len(rows)}**",
        f"- syntax valid: **{sum(bool(row['syntax_valid']) for row in rows)}/{len(rows)}**",
        f"- PARSE_ONLY: **{counts['PARSE_ONLY']}**",
        f"- MODEL_READY: **{counts['MODEL_READY']}**",
        f"- PARTIAL_REPLAY: **{counts['PARTIAL_REPLAY']}**",
        f"- FULL_REPLAY: **{counts['FULL_REPLAY']}**",
        f"- SEMANTIC_VERIFIED: **{counts['SEMANTIC_VERIFIED']}**",
        f"- STATIC_ELIGIBLE: **{eligibility['STATIC_ELIGIBLE']}**",
        f"- STATIC_PARTIAL: **{eligibility['STATIC_PARTIAL']}**",
        f"- RUNTIME_REQUIRED: **{eligibility['RUNTIME_REQUIRED']}**",
        f"- Raw Corpus Coverage: **{raw_pass}/{len(rows)} = {(raw_pass / len(rows) * 100 if rows else 0):.2f}%**",
        f"- Static-Scope Coverage: **{static_pass}/{len(static_scope)} = {(static_pass / len(static_scope) * 100 if static_scope else 0):.2f}%**",
        "",
        "> `MODEL_READY` 表示 AST 已产生 allocator IR；`FULL_REPLAY` 仍不等于外部真值校准。",
        "> 自定义 allocator、服务端隐式 malloc、竞态和动态分支必须配 behavior profile / pwndbg checkpoint，禁止猜测。",
        "",
        "| status | eligibility | ops | chunks | aborted | reason | EXP | artifact |",
        "|---|---|---:|---:|:---:|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['model_status']} | {row['static_eligibility']} | {row['operation_count']} | {row['chunk_count']} | "
            f"{'yes' if row['aborted'] else 'no'} | {'; '.join(row.get('failure_reasons', []))} | "
            f"`{row['path']}` | `{row['artifact']}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch-evaluate a local EXP corpus with deterministic HeapViz AST")
    parser.add_argument("root", type=Path, help="corpus root, e.g. C:/Users/WYH/Desktop/sunshine 附件")
    parser.add_argument("--output", type=Path, default=Path("artifacts/sunshine_ast_v010"))
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"corpus root does not exist: {root}")
    output.mkdir(parents=True, exist_ok=True)
    rows = [evaluate_file(path, root, output) for path in _candidate_paths(root)]
    ready = {"MODEL_READY", "PARTIAL_REPLAY", "FULL_REPLAY", "SEMANTIC_VERIFIED"}
    static_scope = [row for row in rows if row["static_eligibility"] != "RUNTIME_REQUIRED"]
    raw_pass = sum(str(row["model_status"]) in ready for row in rows)
    static_pass = sum(str(row["model_status"]) in ready for row in static_scope)
    payload = {
        "schema_version": 3,
        "root": str(root),
        "case_count": len(rows),
        "metrics": {
            "raw_coverage": {"passed": raw_pass, "total": len(rows), "rate": raw_pass / len(rows) if rows else 0.0},
            "static_scope_coverage": {
                "passed": static_pass,
                "total": len(static_scope),
                "rate": static_pass / len(static_scope) if static_scope else 0.0,
            },
            "eligibility": dict(Counter(str(row["static_eligibility"]) for row in rows)),
        },
        "cases": rows,
    }
    (output / "report.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "REPORT.md").write_text(render_markdown(root, rows), encoding="utf-8")
    print(render_markdown(root, rows).split("\n| status", 1)[0].rstrip())
    print(f"report: {output / 'REPORT.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
