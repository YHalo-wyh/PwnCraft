#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BinaryIR — structured program facts from binary analysis (VNext.1).

Turns ida_bridge's raw facts into the structured representation the
Intelligence Engine consumes:

  * BinaryIR: functions, allocator call-sites (caller + call count), menu
    handler candidates, global objects
  * Evidence records: first-class, individually citable facts
    (the "Evidence #384" model) with provenance and confidence
  * BehaviorLabel vocabulary (VNext.2 classifier output space)

Deterministic only: everything here is derived from actual binary analysis
results. Hypotheses/semantics are formed ABOVE this layer, never inside it.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

ALLOCATOR_SYMBOLS = ("malloc", "calloc", "realloc", "free")

# VNext.2 behavior-label vocabulary: the semantic classifier's output space.
# Function-level labels describe what a handler DOES to heap objects; the
# training curriculum (GOLD corpus) supplies ground truth per label.
#
# Owner amendment: OBSERVATIONAL labels only — "not seen" is NOT "not
# present". CLEAR_POINTER requires a POST_FREE_NULL_STORE evidence chain;
# INDEX_CHECK_NOT_OBSERVED never becomes NO_INDEX_CHECK.
BEHAVIOR_LABELS = [
    "ALLOCATE_OBJECT",      # calls malloc/calloc/realloc
    "FREE_OBJECT",          # calls free
    "READ_OBJECT",          # prints/sends object content (show)
    "WRITE_OBJECT",         # reads user bytes into object (edit/create content)
    "CLEAR_POINTER",        # requires POST_FREE_NULL_STORE evidence chain
    "CLEAR_POINTER_NOT_OBSERVED",   # free present, no clear seen in scope
    "KEEP_DANGLING_POINTER",        # only with complete-body backend coverage
    "INDEX_CHECK_PRESENT",
    "INDEX_CHECK_NOT_OBSERVED",
    "INDEX_CHECK_BYPASSABLE",
    "INDEX_CHECK_INCOMPLETE",
    "CHECK_SIZE",
    "TRUST_USER_SIZE",
    "COPY_FIXED",
    "COPY_UNBOUNDED",       # read(0, ptr, size) with user-controlled size
    "LEAK_POINTER",
    "LEAK_CONTENT",
    "WRITE_FUNCTION_POINTER",
    "CALL_INDIRECT",
]

# Intermediate semantic-evidence kinds (backend-independent): behavior
# inference consumes THESE, never raw `if free then mov 0` patterns — so
# swapping the backend (IDA / Ghidra / objdump / source AST) never rewrites
# the rules above it.
EVIDENCE_KINDS = [
    "CALL",                 # call <allocator>(args)
    "STORE",                # store value -> slot
    "POST_FREE_NULL_STORE", # CALL free(ptr) then STORE 0 -> same_slot(ptr)
    "CMP_BOUNDS",           # compare index against bound
    "TABLE_ACCESS",         # base[index*width] pointer-table access
    "READ_STDIN",           # read(0, buf, n)
    "WRITE_STDOUT",         # write/printf from object content
    "SIZE_FROM_USER",       # size argument originates from user input
]


@dataclass
class BehaviorFact:
    """Evidence-backed behavior fact (owner spec): never a bare boolean.

    kind       : one of BEHAVIOR_LABELS
    subject    : what the fact is about, e.g. "chunks[idx]"
    confidence : 0.0-1.0
    evidence   : intermediate semantic-evidence records (EVIDENCE_KINDS)
    scope      : where the fact was observed, e.g. "delete_heap@0x400c3a"
    backend    : "source-ast" | "ida-disasm" | "ida-decompile" | "objdump" | ...
    """

    kind: str
    subject: str
    confidence: float
    evidence: list[dict] = field(default_factory=list)
    scope: str = ""
    backend: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CallsiteEvidence:
    """One citable evidence record: a cross-reference to an allocator entry."""

    evidence_id: int
    kind: str                      # "ALLOC_CALL" | "FREE_CALL" | ...
    callee: str                    # "malloc" | "free" | ...
    caller: str                    # function name
    caller_address: str
    call_address: str
    confidence: float = 0.95
    source: str = "IDA_DATAFLOW"   # IDA_DATAFLOW | IDA_DECOMPILER | IDA_DISASM

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FunctionIR:
    name: str
    address: str
    size: str = ""
    menu_role: str = ""            # alloc|free|edit|show|copy|unknown|menu|other
    allocator_calls: dict = field(default_factory=dict)  # symbol -> count
    evidence_ids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BinaryIR:
    schema_version: str = SCHEMA_VERSION
    binary_path: str = ""
    binary_sha256: str = ""
    provenance: dict = field(default_factory=dict)
    functions: list[FunctionIR] = field(default_factory=list)
    allocator_callsites: list[CallsiteEvidence] = field(default_factory=list)
    target_actions: dict = field(default_factory=dict)   # function -> actions
    menu_handlers: dict = field(default_factory=dict)    # semantic -> name
    unknowns: list[str] = field(default_factory=list)
    callsites: list[dict] = field(default_factory=list)  # VNext.2 M2.2 CallSiteIR
    stores: list[dict] = field(default_factory=list)     # VNext.2 M2.3 StoreIR

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "binary_path": self.binary_path,
            "binary_sha256": self.binary_sha256,
            "provenance": self.provenance,
            "functions": [f.to_dict() for f in self.functions],
            "allocator_callsites": [e.to_dict() for e in self.allocator_callsites],
            "callsites": self.callsites,
            "stores": self.stores,
            "target_actions": self.target_actions,
            "menu_handlers": self.menu_handlers,
            "unknowns": self.unknowns,
        }

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                        encoding="utf-8")
        return path


# ---------------------------------------------------------------- extraction

_MENU_ROLE_HINTS = [
    ("create", "alloc"), ("add", "alloc"), ("new", "alloc"), ("alloc", "alloc"),
    ("free", "free"), ("delete", "free"), ("del", "free"), ("remove", "free"),
    ("edit", "edit"), ("change", "edit"), ("update", "edit"),
    ("show", "show"), ("print", "show"), ("view", "show"), ("list", "show"),
    ("menu", "menu"), ("main", "other"),
]


def _menu_role(name: str) -> str:
    lowered = name.lower()
    for hint, role in _MENU_ROLE_HINTS:
        if hint in lowered:
            return role
    return "unknown"


def build_binary_ir(facts: dict, binary_sha256: str = "") -> BinaryIR:
    """Build a BinaryIR from ida_bridge.analyze_binary facts.

    Deterministic extraction only: cross-reference records become evidence;
    counts become target actions. Function-name menu roles are recorded as
    candidate hints (weak evidence), never as proven semantics.
    """
    functions = facts.get("functions") or []
    alloc_xrefs = facts.get("alloc_xrefs") or {}
    metadata = facts.get("metadata") or {}

    ir = BinaryIR(
        binary_path=str(facts.get("binary") or ""),
        binary_sha256=binary_sha256 or str(metadata.get("sha256") or ""),
        provenance={
            "engine": (facts.get("server") or {}).get("name", "ida-pro-mcp"),
            "engine_version": (facts.get("server") or {}).get("version", ""),
            "transport": facts.get("transport", ""),
            "degraded": bool(facts.get("degrade_notes")),
            "degrade_notes": facts.get("degrade_notes") or [],
        },
    )

    evidence_id = 1
    allocator_call_count: dict[str, dict[str, int]] = {}
    for symbol in ALLOCATOR_SYMBOLS:
        payload = alloc_xrefs.get(symbol)
        if not isinstance(payload, dict):
            continue
        xrefs = payload.get("xrefs")
        # v1.7 returns either a JSON blob string or a dict; normalize
        entries = _xref_entries(xrefs)
        kind = "FREE_CALL" if symbol == "free" else "ALLOC_CALL"
        for entry in entries:
            caller_fn = (entry.get("function") or {}) if isinstance(entry, dict) else {}
            caller = str(caller_fn.get("name") or "?")
            ir.allocator_callsites.append(CallsiteEvidence(
                evidence_id=evidence_id,
                kind=kind,
                callee=symbol,
                caller=caller,
                caller_address=str(caller_fn.get("address") or ""),
                call_address=str(entry.get("address") or ""),
            ))
            counts = allocator_call_count.setdefault(caller, {})
            counts[symbol] = counts.get(symbol, 0) + 1
            evidence_id += 1

    for fn in functions:
        if not isinstance(fn, dict):
            continue
        name = str(fn.get("name") or "")
        if not name or name.startswith("."):
            continue  # PLT thunks recorded via callsites, not as handlers
        if name.lower() in ALLOCATOR_SYMBOLS or name.startswith("__"):
            continue  # libc stubs are not challenge handlers
        counts = allocator_call_count.get(name) or {}
        ir.functions.append(FunctionIR(
            name=name,
            address=str(fn.get("address") or ""),
            size=str(fn.get("size") or ""),
            menu_role=_menu_role(name),
            allocator_calls=counts,
        ))

    # target actions: N allocator events per handler (the 1:N truth source)
    for fn_ir in ir.functions:
        actions = []
        for symbol, count in sorted(fn_ir.allocator_calls.items()):
            for i in range(count):
                actions.append({
                    "action": "malloc" if symbol in ("malloc", "calloc", "realloc")
                              else "free",
                    "symbol": symbol,
                    "instance": i + 1,
                    "request_argument": None,
                    # argument roles need instruction-level evidence
                    # (VNext.2 semantic recognition); explicit unknown now
                    "evidence": ["IDA_DATAFLOW"],
                })
        if actions or fn_ir.menu_role in ("alloc", "free", "edit", "show"):
            ir.target_actions[fn_ir.name] = {
                "menu_role_hint": fn_ir.menu_role,
                "actions": actions,
            }

    # menu handler candidates by name (weak hints, clearly labeled)
    for fn_ir in ir.functions:
        if fn_ir.menu_role in ("alloc", "free", "edit", "show"):
            ir.menu_handlers.setdefault(fn_ir.menu_role, fn_ir.name)

    if not ir.menu_handlers:
        ir.unknowns.append("menu handler mapping: 函数名无可识别菜单语义, "
                           "需要 VNext.2 汇编/dispatch 证据")
    for symbol in ALLOCATOR_SYMBOLS:
        payload = alloc_xrefs.get(symbol)
        if payload is None:
            continue
        if not isinstance(payload, dict):
            ir.unknowns.append(f"{symbol}: xref 提取失败 ({str(payload)[:60]})")
        elif not _xref_entries(payload.get("xrefs")):
            ir.unknowns.append(f"{symbol}: 无有效 xref 条目 ({str(payload.get('xrefs'))[:60]})")
    return ir


def _xref_entries(xrefs: Any) -> list[dict]:
    """get_xrefs_to returns a JSON string (possibly SEVERAL consecutive
    JSON objects — one per call site), a wrapped list, or a single entry
    dict; normalize to a list of entries."""
    if isinstance(xrefs, str):
        text = xrefs.strip()
        if not text.startswith("{"):
            return []
        entries, decoder, pos = [], json.JSONDecoder(), 0
        while pos < len(text):
            while pos < len(text) and text[pos] in " \t\r\n":
                pos += 1
            if pos >= len(text):
                break
            try:
                obj, end = decoder.raw_decode(text, pos)
            except ValueError:
                break
            if isinstance(obj, dict):
                entries.append(obj)
            pos = end
        xrefs = entries
    if isinstance(xrefs, dict):
        for key in ("xrefs", "data", "result", "content"):
            if key in xrefs:
                xrefs = xrefs[key]
                break
    if isinstance(xrefs, dict):
        # a bare single entry (v1.7 returns one object per call site)
        if "address" in xrefs:
            return [xrefs]
        return []
    if isinstance(xrefs, list):
        return [x for x in xrefs if isinstance(x, dict)]
    return []


def build_from_binary(binary_path: str | Path, *, timeout: float = 300.0) -> BinaryIR:
    """Convenience: analyze the binary with ida_bridge, then build the IR."""
    from pwnbao.core.ida_bridge import analyze_binary

    binary = Path(binary_path)
    facts = analyze_binary(binary, timeout=timeout)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    return build_binary_ir(facts, binary_sha256=digest)


# ---------------------------------------------------------------- profile

def build_behavior_profile(ir: BinaryIR, bindings: list[dict], *,
                           name: str = "") -> tuple[dict, list[str]]:
    """Convert BinaryIR facts + explicit handler bindings into a
    ChallengeBehaviorProfile-compatible dict (M1 plumbing).

    Each binding ties an EXP-side helper name to a BinaryIR function and its
    allocator effects:

        {"helper": "create",              # EXP-side function name
         "binary_handler": "create_heap", # BinaryIR function (validated)
         "menu": "1",
         "parameters": ["size", "content"],
         "effects": [{"kind": "alloc", "chunk": "S", "request_size": "0x10",
                      "bind_handle": false, "note": "management struct"}, ...],
         "bindings_provenance": "analyst-truth (VNext.2 M1)"}

    Deterministic cross-checks (recorded as warnings, never silently fixed):
      * binary_handler must exist in the IR;
      * effect malloc/free counts must match the IR's callsite evidence
        counts for that handler (a mismatch means the bindings and the
        binary disagree — the discrepancy stays visible).
    """
    warnings: list[str] = []
    ir_functions = {f.name: f for f in ir.functions}
    callsites: dict[str, dict[str, int]] = {}
    for e in ir.allocator_callsites:
        by_symbol = callsites.setdefault(e.caller, {})
        by_symbol[e.callee] = by_symbol.get(e.callee, 0) + 1

    helpers = []
    for binding in bindings:
        helper = str(binding.get("helper") or "")
        handler = str(binding.get("binary_handler") or "")
        fn_ir = ir_functions.get(handler)
        if fn_ir is None:
            warnings.append(f"binding {helper}: binary_handler {handler!r} "
                            "不在 BinaryIR 函数表中")
        effects = [dict(e) for e in (binding.get("effects") or [])]
        if fn_ir is not None:
            for symbol in ALLOCATOR_SYMBOLS:
                effect_count = sum(1 for e in effects
                                   if e.get("kind") == ("delete" if symbol == "free"
                                                        else "alloc")
                                   and symbol == ("free" if e.get("kind") == "delete"
                                                  else "malloc"))
                ir_count = (callsites.get(handler) or {}).get(symbol, 0)
                if effect_count and ir_count and effect_count != ir_count:
                    warnings.append(
                        f"binding {helper}: effects 含 {effect_count} 个 {symbol} "
                        f"但 BinaryIR 证据为 {ir_count} 个 {symbol} 调用 "
                        f"(差异保留可见, 不静默修正)")
        helpers.append({
            "function": helper,
            "receiver": "",
            "parameters": list(binding.get("parameters") or []),
            "defaults": dict(binding.get("defaults") or {}),
            "effects": effects,
            "evidence": str(binding.get("bindings_provenance")
                            or "BinaryIR-derived behavior profile"),
        })
    profile = {"version": 1, "name": name, "helpers": helpers}
    return profile, warnings
