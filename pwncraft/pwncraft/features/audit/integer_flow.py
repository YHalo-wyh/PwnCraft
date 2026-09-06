"""Evidence-gated composition for C signedness flows and EXP input literals.

This module sits above :mod:`pwncraft.core.c_source_ir`.  The source extractor
proves parser/storage/consumer relations; this layer may compose those facts
with literal protocol input present in an exploit source.  It never executes the
exploit and never upgrades source+EXP evidence into a runtime observation.

Cycle-13 deliberately keeps the supported shape narrow:

* a source variable is obtained from ``find_header(..., "Field")``;
* ``that_variable->val`` is consumed by the signed parser already recognized by
  ``extract_c_integer_flows``;
* a Python EXP contains a literal HTTP-style ``Field: signed-decimal`` line.

Unknown or indirect shapes remain UNKNOWN instead of being guessed.
"""
from __future__ import annotations

import ast
import re
from dataclasses import replace
from typing import Any

from pwncraft.core.c_source_ir import CIntegerFlowFact, extract_c_integer_flows


# This is intentionally a function-header recognizer rather than a C parser.  It
# accepts pointer-return functions and common multi-token return types while
# explicitly excluding control statements.  The body is still brace matched.
_FUNCTION_HEADER_RE = re.compile(
    r"^\s*(?!if\b|for\b|while\b|switch\b)"
    r"(?:[A-Za-z_]\w*|\*|\s)+?"
    r"(?P<name>[A-Za-z_]\w*)\s*"
    r"\((?P<params>[^;{}]*)\)\s*\{"
)
_HEADER_BIND_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*"
    r"find_header\s*\([^,]+,\s*\"(?P<field>[^\"]+)\"\s*\)"
)
_PARSER_HEADER_VALUE_RE = re.compile(
    r"\bstrto(?:l|ll)\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*->\s*val\b"
)


def _function_spans(source: str) -> list[tuple[str, int, int]]:
    """Return conservative 1-based function spans for ordinary C definitions."""
    lines = source.splitlines()
    spans: list[tuple[str, int, int]] = []
    i = 0
    while i < len(lines):
        match = _FUNCTION_HEADER_RE.match(lines[i])
        if match is None:
            i += 1
            continue
        depth = 0
        j = i
        while j < len(lines):
            # This remains intentionally lexical.  Braces inside exotic macro or
            # string constructs may defeat it; such cases simply should not be
            # promoted by this evidence layer.
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0 and j > i:
                break
            j += 1
        spans.append((match.group("name"), i + 1, min(j + 1, len(lines))))
        i = max(j + 1, i + 1)
    return spans


def _function_for_line(spans: list[tuple[str, int, int]], line: int) -> str:
    for name, start, end in spans:
        if start <= line <= end:
            return name
    return "<global>"


def _scoped_source_facts(source: str) -> list[CIntegerFlowFact]:
    """Attach function provenance using the source line when the low-level
    extractor could not recognize a pointer-return function header.

    This does not alter any semantic fact; it only repairs the scope/provenance
    label from the same source text.
    """
    spans = _function_spans(source)
    result: list[CIntegerFlowFact] = []
    for fact in extract_c_integer_flows(source):
        function = fact.function
        if function == "<global>":
            rebound = _function_for_line(spans, fact.line)
            if rebound != "<global>":
                fact = replace(fact, function=rebound)
        result.append(fact)
    return result


def _header_bindings(source: str) -> dict[tuple[str, str], str]:
    spans = _function_spans(source)
    bindings: dict[tuple[str, str], str] = {}
    for line_no, line in enumerate(source.splitlines(), start=1):
        match = _HEADER_BIND_RE.search(line)
        if match is None:
            continue
        function = _function_for_line(spans, line_no)
        bindings[(function, match.group("var"))] = match.group("field")
    return bindings


def _seed_input_field(
    fact: CIntegerFlowFact,
    bindings: dict[tuple[str, str], str],
) -> str | None:
    match = _PARSER_HEADER_VALUE_RE.search(fact.expression)
    if match is None:
        return None
    return bindings.get((fact.function, match.group("var")))


def _python_literal_strings(source: str) -> tuple[list[tuple[str, int]], ast.SyntaxError | None]:
    try:
        tree = ast.parse(source or "")
    except SyntaxError as error:
        return [], error
    values: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        if isinstance(node.value, bytes):
            values.append((node.value.decode("latin-1"), int(getattr(node, "lineno", 0) or 0)))
        elif isinstance(node.value, str):
            values.append((node.value, int(getattr(node, "lineno", 0) or 0)))
    return values, None


def _literal_field_values(
    literals: list[tuple[str, int]], field: str
) -> list[tuple[int, int, str]]:
    pattern = re.compile(
        rf"(?im)(?:^|\r?\n)\s*{re.escape(field)}\s*:\s*([+-]?\d+)\s*(?=\r?$|\r?\n)"
    )
    result: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int]] = set()
    for text, line in literals:
        for match in pattern.finditer(text):
            try:
                value = int(match.group(1), 10)
            except ValueError:
                continue
            key = (line, value)
            if key in seen:
                continue
            seen.add(key)
            result.append((value, line, match.group(0).strip()))
    return result


def _allocation_is_plus_one(expression: str, variable: str) -> bool:
    # We only need the exact modular identity MAX + 1 -> 0 in this cycle.
    escaped = re.escape(variable)
    return bool(
        re.search(rf"\b{escaped}\b\s*\+\s*1\b", expression)
        or re.search(rf"\b1\s*\+\s*{escaped}\b", expression)
    )


def analyze_c_integer_exp_flow(c_source: str, exp_source: str) -> dict[str, Any]:
    """Compose source facts with literal EXP protocol inputs.

    Returned ``composed_facts`` are evidence relations, not runtime facts.  In
    particular, ``-1`` converted to an unsigned destination is exactly the
    destination maximum for *any* destination width N, and adding one then
    yields zero modulo ``2**N``.  This arithmetic statement does not assert that
    ``malloc`` succeeds, that a read completes, or that corruption is reached.
    """
    literals, syntax_error = _python_literal_strings(exp_source)
    source_facts = _scoped_source_facts(c_source)
    source_dicts = [fact.to_dict() for fact in source_facts]
    if syntax_error is not None:
        return {
            "status": "blocked",
            "reason": "EXP_PARSE",
            "line": syntax_error.lineno or 0,
            "message": syntax_error.msg,
            "source_facts": source_dicts,
            "composed_facts": [],
        }

    bindings = _header_bindings(c_source)
    composed: list[dict[str, Any]] = []
    seeds = [fact for fact in source_facts if fact.kind == "SIGNED_PARSE_TO_UNSIGNED"]

    for seed in seeds:
        field = _seed_input_field(seed, bindings)
        if not field:
            continue
        witnesses = _literal_field_values(literals, field)
        if not witnesses:
            continue

        allocations = [
            fact for fact in source_facts
            if fact.kind == "UNSIGNED_LENGTH_ALLOCATION_USE"
            and fact.function == seed.function
            and fact.variable == seed.variable
        ]
        copy_bounds = [
            fact for fact in source_facts
            if fact.kind == "UNSIGNED_LENGTH_COPY_BOUND_USE"
            and fact.function == seed.function
            and fact.variable == seed.variable
        ]

        for value, exp_line, fragment in witnesses:
            base = {
                "function": seed.function,
                "variable": seed.variable,
                "input_field": field,
                "input_value": value,
                "source_line": seed.line,
                "exp_line": exp_line,
                "provenance": ["OFFICIAL_OR_USER_SOURCE", "EXP_AST_LITERAL"],
            }
            composed.append({
                "kind": "EXP_INPUT_REACHES_SIGNED_PARSER",
                **base,
                "evidence": fragment,
                "limitations": ["source+EXP evidence only; runtime delivery is not observed"],
            })

            # -1 has a width-independent exact unsigned conversion identity:
            # (-1) mod 2**N == 2**N - 1.  Do not generalize other negative
            # inputs into an exact maximum.
            if value != -1:
                continue

            composed.append({
                "kind": "UNSIGNED_CONVERSION_EXACT_MAX",
                **base,
                "relation": "(-1) mod 2^N = 2^N - 1",
                "destination_type": seed.details.get("destination_type", "unsigned"),
                "destination_width": "N (from target ABI/type facts)",
                "limitations": ["does not by itself prove a memory-safety impact"],
            })

            for allocation in allocations:
                if not _allocation_is_plus_one(allocation.expression, seed.variable):
                    continue
                composed.append({
                    "kind": "ALLOCATION_ARGUMENT_WRAP_TO_ZERO",
                    **base,
                    "allocation_expression": allocation.expression,
                    "allocation_line": allocation.line,
                    "relation": "(2^N - 1 + 1) mod 2^N = 0",
                    "result": 0,
                    "limitations": [
                        "records the C unsigned argument value only",
                        "does not claim malloc(0) result or allocator behavior",
                    ],
                })

            for copy in copy_bounds:
                composed.append({
                    "kind": "COPY_BOUND_REMAINS_UNSIGNED_MAX",
                    **base,
                    "copy_expression": copy.expression,
                    "copy_line": copy.line,
                    "relation": "copy bound = 2^N - 1",
                    "result": "UNSIGNED_MAX(N)",
                    "limitations": [
                        "does not claim the full read completes",
                        "does not claim a specific overwrite extent without runtime evidence",
                    ],
                })

    return {
        "status": "ok",
        "reason": "",
        "source_facts": source_dicts,
        "composed_facts": composed,
    }
