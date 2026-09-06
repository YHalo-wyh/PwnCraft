"""fmt 格式化字符串语义检查 (VNext M4 fmt 深化, 确定性)。

从 EXP 字符串字面量提取格式化说明符, 输出确定性事实:
  FMT_WRITE_N       %n / %hn / %ln 出现 → 任意写原语面 (informational fact)
  FMT_POSITIONAL    位置参数 %N$xx 使用 (地址派生常用)
  FMT_CONVERSIONS   转换说明符清单与计数

泄漏 (无 %n) 与写入 (%n) 是不同原语面, 分开呈现, 不下漏洞结论。
"""
from __future__ import annotations

import re
from typing import Any

_SPEC_RE = re.compile(
    r"%(?:(\d+)\$)?(%*[-+ #0]*\d*(?:\.\d+)?(?:hh|h|l|ll|q|j|z|t)?([diouxXeEfFgGaAcspn]))"
)


def parse_format(spec_text: str) -> dict[str, Any]:
    conversions: list[dict] = []
    for m in _SPEC_RE.finditer(spec_text or ""):
        positional, length, conv = m.group(1), m.group(2) or "", m.group(3)
        conversions.append({
            "positional": int(positional) if positional else None,
            "length_modifier": length,
            "conversion": conv,
            "write": conv in ("n",),
        })
    writes = [c for c in conversions if c["write"]]
    positional_uses = [c for c in conversions if c["positional"] is not None]
    return {
        "conversions": conversions,
        "conversion_count": len(conversions),
        "has_write": bool(writes),
        "writes": writes,
        "positional_uses": positional_uses,
    }


def fmt_facts_from_strings(strings: list[str]) -> list[dict]:
    """对 EXP 中所有字符串字面量跑 parse_format, 输出 BehaviorFact 形状。"""
    facts: list[dict] = []
    for text in strings:
        parsed = parse_format(text)
        if parsed["conversion_count"] == 0:
            continue
        evidence = [{"kind": "FMT_CONVERSIONS",
                     "detail": f"{parsed['conversion_count']} conversions in "
                               f"{text[:60]!r}"}]
        if parsed["has_write"]:
            facts.append({
                "kind": "WRITE_FORMAT_STRING",
                "subject": text[:60],
                "confidence": 0.95,
                "evidence": evidence + [{"kind": "FMT_WRITE_N",
                                         "detail": "%n 类写转换出现"}],
                "backend": "source-ast",
            })
        elif parsed["positional_uses"]:
            facts.append({
                "kind": "LEAK_CONTENT",
                "subject": text[:60],
                "confidence": 0.85,
                "evidence": evidence + [{"kind": "FMT_POSITIONAL",
                                         "detail": f"{len(parsed['positional_uses'])} 位置参数引用"}],
                "backend": "source-ast",
            })
    return facts
