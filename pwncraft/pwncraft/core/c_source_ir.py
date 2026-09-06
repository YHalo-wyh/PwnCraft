"""Source-level deterministic facts for small CTF challenge programs.

The original VNext.2 backend extracts a conservative subset of C callsites into
CallSiteIR.  This module deliberately remains *not* a general C parser:
unsupported constructs stay UNKNOWN rather than being guessed.

Cycle-12 adds a second, orthogonal fact extractor for signed-to-unsigned length
flows.  It records evidence chains (parser result -> unsigned storage ->
allocation/copy uses); it does not label a vulnerability merely because a
function such as strtoll/malloc/read appears in the source.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any

from pwncraft.core.value_ir import (
    CallSiteIR, K_ARG, K_CONST, K_GLOBAL, K_LOAD, K_CALL_RESULT, K_EXPR,
    K_UNKNOWN, StoreIR, ValueIR,
)

_FUNC_RE = re.compile(r"^\s*(?:void|int|size_t|char\s*\*|long)\s+(\w+)\s*\(([^)]*)\)\s*\{")
_CALL_RE = re.compile(r"(\w+)\s*\(")
_INDEX_RE = re.compile(r"(\w+)\s*\[\s*([A-Za-z_]\w*)\s*\]")

# Narrow source-fact vocabulary.  The parser family is intentionally limited to
# functions whose return signedness is well-defined by the C library API.
_SIGNED_PARSERS = {"strtol": 64, "strtoll": 64}
_UNSIGNED_TYPE_RE = re.compile(
    r"\b(size_t|uint(?:8|16|32|64)_t|unsigned(?:\s+(?:char|short|int|long|long\s+long))?)\b"
)
_LENGTH_DECL_RE = re.compile(
    r"\b(?P<type>size_t|uint(?:8|16|32|64)_t|unsigned(?:\s+(?:char|short|int|long|long\s+long))?)"
    r"\s+(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<parser>strtol|strtoll)\s*\((?P<args>[^;]*)\)\s*;"
)
_ALLOC_USE_RE = re.compile(
    r"\b(?P<callee>malloc|calloc|realloc)\s*\((?P<args>[^;]*)\)\s*;"
)
_COPY_CALLEES = {"read", "readn", "recv", "recvfrom", "memcpy", "memmove", "fread"}


@dataclass(frozen=True)
class CIntegerFlowFact:
    """One source-backed fact in a signedness/length evidence chain."""

    kind: str
    function: str
    variable: str
    expression: str
    line: int
    provenance: str = "SOURCE"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _split_args(text: str) -> list[str]:
    """Top-level comma split (bracket/paren aware)."""
    args, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
    if text[start:].strip():
        args.append(text[start:].strip())
    return args


def _value(expr: str, params: list[str], locals_map: dict[str, ValueIR],
           table_globals: dict[str, str]) -> ValueIR:
    """Expression → ValueIR (deterministic, precision-first)."""
    expr = expr.strip().rstrip(";").strip()
    if not expr:
        return ValueIR(kind=K_UNKNOWN, reason="empty")
    if re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", expr):
        return ValueIR(kind=K_CONST, value=int(expr, 0))
    if expr in params:
        return ValueIR(kind=K_ARG, n=params.index(expr))
    if expr in locals_map:
        return locals_map[expr]
    m = _INDEX_RE.fullmatch(expr)
    if m:
        base_name, idx = m.group(1), m.group(2)
        base_addr = table_globals.get(base_name, base_name)
        index = _value(idx, params, locals_map, table_globals)
        return ValueIR(kind=K_LOAD,
                       base=ValueIR(kind=K_GLOBAL, address=base_addr),
                       index=index, scale=8)
    m = re.fullmatch(r"(\w+)\s*->\s*(\w+)", expr)
    if m:
        inner = _value(m.group(1), params, locals_map, table_globals)
        return ValueIR(kind=K_LOAD, base=inner, index=None, scale=1,
                       offset={"content": 8}.get(m.group(2), 0))
    if re.fullmatch(r"\w+", expr):
        return ValueIR(kind=K_UNKNOWN, reason=f"unresolved local {expr}")
    # arithmetic: keep the shape
    for op in ("+", "-", "*"):
        if op in expr:
            left, right = expr.split(op, 1)
            return ValueIR(kind=K_EXPR, op={"*": "mul", "+": "add", "-": "sub"}[op],
                           operands=(_value(left, params, locals_map, table_globals),
                                     _value(right, params, locals_map, table_globals)))
    return ValueIR(kind=K_UNKNOWN, reason=f"unparsed {expr[:40]}")


def _function_spans(source: str) -> list[tuple[str, int, int]]:
    """Return (name, 1-based start line, 1-based end line) for simple functions."""
    lines = source.splitlines()
    spans: list[tuple[str, int, int]] = []
    i = 0
    while i < len(lines):
        m = _FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        depth = 0
        j = i
        while j < len(lines):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0 and j > i:
                break
            j += 1
        spans.append((m.group(1), i + 1, min(j + 1, len(lines))))
        i = max(j + 1, i + 1)
    return spans


def _function_for_line(spans: list[tuple[str, int, int]], line: int) -> str:
    for name, start, end in spans:
        if start <= line <= end:
            return name
    return "<global>"


def _identifier_present(expression: str, variable: str) -> bool:
    return re.search(rf"\b{re.escape(variable)}\b", expression) is not None


def extract_c_integer_flows(source: str) -> list[CIntegerFlowFact]:
    """Extract evidence-backed signedness/length flows from C source.

    Currently proven facts are deliberately narrow:
      1. signed ``strtol``/``strtoll`` result assigned directly to an unsigned
         integer type such as ``size_t``;
      2. that exact variable appearing in malloc/calloc/realloc arguments;
      3. the same variable used as the length/count argument of a bounded set of
         byte-moving APIs.

    This function does *not* claim that a negative value is reachable, that an
    arithmetic wrap occurs at runtime, or that memory corruption succeeds.  A
    caller may combine these source facts with an EXP input or runtime evidence.
    """
    spans = _function_spans(source)
    lines = source.splitlines()
    facts: list[CIntegerFlowFact] = []
    tracked: dict[str, dict[str, Any]] = {}

    for match in _LENGTH_DECL_RE.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        parser = match.group("parser")
        variable = match.group("var")
        c_type = " ".join(match.group("type").split())
        function = _function_for_line(spans, line)
        expression = match.group(0).strip()
        tracked[variable] = {
            "function": function,
            "line": line,
            "type": c_type,
            "parser": parser,
        }
        facts.append(CIntegerFlowFact(
            kind="SIGNED_PARSE_TO_UNSIGNED",
            function=function,
            variable=variable,
            expression=expression,
            line=line,
            details={
                "parser": parser,
                "parser_result": "signed",
                "destination_type": c_type,
                "destination_signedness": "unsigned",
                "negative_input_mapping": "modulo_destination_width",
            },
        ))

    if not tracked:
        return facts

    # Statement-level call scan, retaining line/function provenance.
    for line_no, raw in enumerate(lines, start=1):
        function = _function_for_line(spans, line_no)
        for cm in _CALL_RE.finditer(raw):
            callee = cm.group(1)
            if callee not in _COPY_CALLEES and callee not in {"malloc", "calloc", "realloc"}:
                continue
            depth, k = 0, cm.end() - 1
            start = cm.end()
            while k < len(raw):
                if raw[k] == "(":
                    depth += 1
                elif raw[k] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            if depth != 0:
                continue
            args_text = raw[start:k]
            args = _split_args(args_text)
            for variable, seed in tracked.items():
                # Keep flows function-local unless there is explicit future
                # interprocedural evidence.  This prevents same-name locals from
                # being conflated across handlers.
                if seed["function"] != function:
                    continue
                uses = [idx for idx, arg in enumerate(args)
                        if _identifier_present(arg, variable)]
                if not uses:
                    continue
                if callee in {"malloc", "calloc", "realloc"}:
                    facts.append(CIntegerFlowFact(
                        kind="UNSIGNED_LENGTH_ALLOCATION_USE",
                        function=function,
                        variable=variable,
                        expression=f"{callee}({args_text})",
                        line=line_no,
                        details={"callee": callee, "argument_indexes": uses},
                    ))
                    continue
                # Byte-moving APIs have different length positions.  Only emit a
                # COPY_BOUND fact when the tracked value is actually in a known
                # count/length slot; otherwise the call is not evidence.
                length_positions = {
                    "read": {2}, "readn": {2}, "recv": {2}, "recvfrom": {2},
                    "memcpy": {2}, "memmove": {2}, "fread": {1, 2},
                }.get(callee, set())
                relevant = sorted(set(uses) & length_positions)
                if relevant:
                    facts.append(CIntegerFlowFact(
                        kind="UNSIGNED_LENGTH_COPY_BOUND_USE",
                        function=function,
                        variable=variable,
                        expression=f"{callee}({args_text})",
                        line=line_no,
                        details={"callee": callee,
                                 "length_argument_indexes": relevant},
                    ))
    return facts


def extract_c_callsites(source: str, *,
                        table_globals: dict[str, str] | None = None) -> list[CallSiteIR]:
    """Extract CallSiteIR from C source. table_globals maps array variable
    names to their bss addresses when known (e.g. heaparray → 0x6020a0)."""
    tg = table_globals or {}
    sites: list[CallSiteIR] = []
    lines = source.splitlines()
    i = 0
    while i < len(lines):
        m = _FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        func, params_text = m.group(1), m.group(2)
        params = [p.strip().split()[-1].lstrip("*") for p in params_text.split(",")
                  if p.strip()]
        # brace-matched body
        body_start = i
        depth, j = 0, i
        while j < len(lines):
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 1 and "{" in lines[j]:
                body_start = j + 1
            if depth == 0 and j > i:
                break
            j += 1
        body = "\n".join(lines[body_start:j])
        locals_map: dict[str, ValueIR] = {}
        site_no = 0
        for statement in re.split(r";", body):
            st = statement.strip()
            if not st:
                continue
            # assignment: lhs = rhs (rhs may contain calls)
            am = re.match(r"(.+?)\s*=\s*(.+)", st, re.S)
            calls = list(_CALL_RE.finditer(st))
            for cm in calls:
                callee = cm.group(1)
                if callee in ("if", "while", "for", "switch", "sizeof", "return"):
                    continue
                # paren-matched argument text
                depth, k = 0, cm.end() - 1
                start = cm.end()
                while k < len(st):
                    if st[k] == "(":
                        depth += 1
                    elif st[k] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    k += 1
                arg_text = st[start:k]
                args = [_value(a, params, locals_map, tg)
                        for a in _split_args(arg_text)]
                args = [a for a in args if a.kind != K_UNKNOWN or
                        a.reason.startswith(("unresolved", "unparsed"))]
                site_addr = f"{func}:{site_no}:{cm.start()}"
                site_no += 1
                result = ValueIR(kind=K_CALL_RESULT, callee=callee, site=site_addr) \
                    if callee in ("malloc", "calloc", "realloc") else None
                sites.append(CallSiteIR(
                    address=site_addr, function=func, callee=callee,
                    args=tuple(args), result=result,
                    span_start=site_addr, span_end=site_addr))
                if result is not None and am and _INDEX_RE.fullmatch(am.group(1).strip()):
                    pass  # store handled below via StoreIR
            if am:
                lhs, rhs = am.group(1).strip(), am.group(2).strip()
                if _INDEX_RE.fullmatch(lhs):
                    m2 = _INDEX_RE.match(lhs)
                    base_name, idx = m2.group(1), m2.group(2)
                    base_addr = tg.get(base_name, base_name)
                    slot = ValueIR(kind=K_LOAD,
                                   base=ValueIR(kind=K_GLOBAL, address=base_addr),
                                   index=_value(idx, params, locals_map, tg), scale=8)
                    rhs_v = _value(rhs, params, locals_map, tg)
                    sites.append(CallSiteIR(
                        address=f"{func}:store:{lhs}", function=func,
                        callee="<store>", args=(slot, rhs_v)))
                    locals_map["__last_store_target__"] = slot
                elif re.fullmatch(r"\w+", lhs) and rhs:
                    rhs_v = _value(rhs, params, locals_map, tg)
                    if rhs_v.kind != K_UNKNOWN:
                        locals_map[lhs] = rhs_v
        i = j
    return sites
