"""Source-AST backend (VNext.2 M2 cross-validation): minimal deterministic
C callsite extraction → the SAME CallSiteIR the binary tracer produces.

Scope: statement-level patterns needed for menu-style heap challenges
(calls with expressions, `ptr = malloc(n)`, `table[i] = expr`, `table[i] = NULL`).
NOT a C parser: unknown constructs → UNKNOWN values. Precision > recall.
"""
from __future__ import annotations

import re
from typing import Any

from pwnbao.core.value_ir import (
    CallSiteIR, K_ARG, K_CONST, K_GLOBAL, K_LOAD, K_CALL_RESULT, K_EXPR,
    K_UNKNOWN, StoreIR, ValueIR,
)

_FUNC_RE = re.compile(r"^\s*(?:void|int|size_t|char\s*\*|long)\s+(\w+)\s*\(([^)]*)\)\s*\{")
_CALL_RE = re.compile(r"(\w+)\s*\(")
_INDEX_RE = re.compile(r"(\w+)\s*\[\s*([A-Za-z_]\w*)\s*\]")


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
