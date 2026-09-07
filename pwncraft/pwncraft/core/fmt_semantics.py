"""Deterministic printf-format semantics.

The parser separates four facts that must not be conflated:
- a conversion exists;
- a positional argument is selected;
- a %n-family conversion writes through an argument pointer;
- the exact byte count/value written is statically known.

Seeing ``%n`` is therefore a write surface, not proof of an arbitrary write.
"""
from __future__ import annotations

import re
from typing import Any

_SPEC_RE = re.compile(
    r"%"
    r"(?:(?P<position>\d+)\$)?"
    r"(?P<flags>[-+ #0']*)"
    r"(?:(?P<width>\d+)|\*(?:(?P<width_position>\d+)\$)?)?"
    r"(?:\.(?:(?P<precision>\d+)|\*(?:(?P<precision_position>\d+)\$)?))?"
    r"(?P<length>hh|ll|h|l|q|j|z|t)?"
    r"(?P<conversion>[diouxXeEfFgGaAcspn%])"
)


def _write_width(length: str, *, abi: str) -> int | None:
    if length == "hh":
        return 1
    if length == "h":
        return 2
    if length in ("", None):
        return 4
    if length in ("l", "ll", "q"):
        return 8 if abi in ("amd64_sysv", "x86_64_sysv", "lp64") else None
    # j/z/t are ABI/type-definition dependent.  Keep them unresolved unless a
    # future reviewed ABI policy supplies their concrete width.
    return None


def parse_format(spec_text: str, *, abi: str = "amd64_sysv") -> dict[str, Any]:
    text = spec_text or ""
    conversions: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    positional_uses: list[dict[str, Any]] = []
    counted_writes: list[dict[str, Any]] = []

    count: int | None = 0
    cursor = 0
    for match in _SPEC_RE.finditer(text):
        if count is not None:
            count += match.start() - cursor
        cursor = match.end()

        position = int(match.group("position")) if match.group("position") else None
        width_position = (
            int(match.group("width_position")) if match.group("width_position") else None
        )
        precision_position = (
            int(match.group("precision_position")) if match.group("precision_position") else None
        )
        width = int(match.group("width")) if match.group("width") else None
        precision = int(match.group("precision")) if match.group("precision") else None
        length = match.group("length") or ""
        conversion = match.group("conversion")
        dynamic_width = "*" in match.group(0).split(".", 1)[0]
        dynamic_precision = bool("." in match.group(0) and "*" in match.group(0).split(".", 1)[1])

        item: dict[str, Any] = {
            "raw": match.group(0),
            "positional": position,
            "width": width,
            "width_positional": width_position,
            "precision": precision,
            "precision_positional": precision_position,
            "length_modifier": length,
            "conversion": conversion,
            "write": conversion == "n",
            "write_width": _write_width(length, abi=abi) if conversion == "n" else None,
            "count_before": count,
        }

        if conversion == "%":
            if count is not None:
                count += 1
        elif conversion == "n":
            write = dict(item)
            write["target_argument_index"] = position
            if count is not None and item["write_width"] is not None:
                modulus = 1 << (8 * int(item["write_width"]))
                write["value_modulo"] = count % modulus
                write["exact_value_known"] = True
                counted_writes.append(dict(write))
            else:
                write["value_modulo"] = None
                write["exact_value_known"] = False
            writes.append(write)
        elif conversion == "c" and not dynamic_width and not dynamic_precision:
            # %c emits one character; a literal field width deterministically
            # pads it to max(width, 1).  The argument value does not affect size.
            if count is not None:
                count += max(width or 1, 1)
        else:
            # Integer/string/pointer/floating conversions have value-dependent
            # output length.  A literal width is only a minimum, not an exact
            # count, so later %n values become unknown.
            count = None

        if position is not None or width_position is not None or precision_position is not None:
            positional_uses.append(item)
        conversions.append(item)

    if count is not None:
        count += len(text) - cursor

    return {
        "conversions": conversions,
        "conversion_count": len(conversions),
        "has_write": bool(writes),
        "writes": writes,
        "counted_writes": counted_writes,
        "positional_uses": positional_uses,
        "final_output_count": count,
        "abi": abi,
    }


def fmt_facts_from_strings(strings: list[str]) -> list[dict]:
    """Run deterministic format parsing over EXP string literals."""
    facts: list[dict] = []
    for text in strings:
        parsed = parse_format(text)
        if parsed["conversion_count"] == 0:
            continue
        evidence = [{
            "kind": "FMT_CONVERSIONS",
            "detail": f"{parsed['conversion_count']} conversions in {text[:60]!r}",
        }]
        if parsed["has_write"]:
            for write in parsed["writes"]:
                write_evidence = evidence + [{
                    "kind": "FMT_WRITE_N",
                    "detail": (
                        f"{write['raw']} writes width={write['write_width']} "
                        f"through argument={write['target_argument_index']}"
                    ),
                }]
                fact: dict[str, Any] = {
                    "kind": "WRITE_FORMAT_STRING",
                    "subject": text[:60],
                    "confidence": 0.95,
                    "write_conversion": write["raw"],
                    "target_argument_index": write["target_argument_index"],
                    "write_width": write["write_width"],
                    "exact_write_value_known": bool(write.get("exact_value_known")),
                    "write_value_modulo": write.get("value_modulo"),
                    "evidence": write_evidence,
                    "backend": "source-ast",
                }
                if write.get("exact_value_known"):
                    fact["evidence"] = write_evidence + [{
                        "kind": "FMT_COUNTED_WRITE",
                        "detail": f"exact preceding output count={write['count_before']}",
                    }]
                facts.append(fact)
        elif parsed["positional_uses"]:
            facts.append({
                "kind": "LEAK_CONTENT",
                "subject": text[:60],
                "confidence": 0.85,
                "evidence": evidence + [{
                    "kind": "FMT_POSITIONAL",
                    "detail": f"{len(parsed['positional_uses'])} positional references",
                }],
                "backend": "source-ast",
            })
    return facts
